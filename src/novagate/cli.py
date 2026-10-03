"""``novagate`` command line interface.

novagate serve                    # run the gateway
novagate inspect "your prompt"    # one-shot verdict, no server
novagate scan -f prompts.txt      # batch check a file
novagate categories               # list the detection catalog
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from novagate import __version__
from novagate.config import settings
from novagate.console import print_gateway_header
from novagate.evaluator import VectorThreatEvaluator
from novagate.signatures import CATEGORIES


def _inspect_one(evaluator: VectorThreatEvaluator, prompt: str, as_json: bool) -> int:
    """Return a process exit code: 0 pass, 1 review, 2 block."""
    blocked, telemetry, report = evaluator.inspect(prompt)

    if as_json:
        print(
            json.dumps(
                {
                    "verdict": telemetry["verdict"],
                    "blocked": blocked,
                    "risk_index": telemetry["calculated_risk_index"],
                    "categories": telemetry["categories_triggered"],
                    "layers": report.layers_unwrapped,
                    "decoded": report.primary,
                    "payload_sha256": report.payload_sha256,
                },
                indent=2,
            )
        )
        return 2 if blocked else (1 if telemetry["needs_review"] else 0)

    status = "BLOCKED" if blocked else ("REVIEW" if telemetry["needs_review"] else "PASS")
    print(f"verdict   : {status}")
    print(f"risk      : {telemetry['calculated_risk_index']} / 10.0")
    print(f"categories: {', '.join(telemetry['categories_triggered']) or 'none'}")
    print(f"layers    : {', '.join(report.layers_unwrapped) or 'none'}")
    print(f"decoded   : {report.primary[:200]}")
    return 2 if blocked else (1 if telemetry["needs_review"] else 0)


def cmd_inspect(args: argparse.Namespace) -> int:
    evaluator = VectorThreatEvaluator()
    return _inspect_one(evaluator, args.prompt, args.json)


def cmd_scan(args: argparse.Namespace) -> int:
    evaluator = VectorThreatEvaluator()
    source = Path(args.file)
    if not source.is_file():
        print(f"error: {source} is not a readable file", file=sys.stderr)
        return 3

    blocked = reviewed = passed = 0
    rows = []
    for lineno, line in enumerate(source.read_text(encoding="utf-8").splitlines(), 1):
        prompt = line.strip()
        if not prompt or prompt.startswith("#"):
            continue
        is_blocked, telemetry, report = evaluator.inspect(prompt)
        if is_blocked:
            blocked += 1
        elif telemetry["needs_review"]:
            reviewed += 1
        else:
            passed += 1
        rows.append(
            {
                "line": lineno,
                "verdict": telemetry["verdict"],
                "risk": telemetry["calculated_risk_index"],
                "categories": telemetry["categories_triggered"],
                "prompt": prompt[:70],
            }
        )

    if args.json:
        print(
            json.dumps(
                {
                    "summary": {"blocked": blocked, "review": reviewed, "passed": passed},
                    "results": rows,
                },
                indent=2,
            )
        )
    else:
        for row in rows:
            print(
                f"{row['line']:>5}  {row['verdict']:<8} {row['risk']:>5}  "
                f"{','.join(row['categories'])[:44]:<44} {row['prompt']}"
            )
        print(f"\n{len(rows)} prompts: {blocked} blocked, {reviewed} review, {passed} passed")
    return 2 if blocked else 0


def cmd_categories(_: argparse.Namespace) -> int:
    print(f"{'CATEGORY':<26} {'CRIT':>5} {'HARD':>5}  DESCRIPTION")
    for category in CATEGORIES:
        print(
            f"{category.name:<26} {category.base_criticality:>5} "
            f"{'yes' if category.hard_block else '-':>5}  {category.description}"
        )
    print(f"\nBlock threshold: {settings.block_threshold}/10.0")
    print(f"Review threshold: {settings.review_threshold}/10.0")
    return 0


def cmd_serve(args: argparse.Namespace) -> int:
    import uvicorn

    from novagate.app import app

    host = args.host or settings.host
    port = args.port or settings.port

    if not settings.is_loopback and not (settings.api_key or settings.require_auth):
        print(
            "Refusing to start: NovaGate would listen on a non-loopback address "
            "with no API key.\n"
            "Set NOVAGATE_API_KEY, or pass --host 127.0.0.1.",
            file=sys.stderr,
        )
        return 4

    print_gateway_header(__version__)
    print(f"[+] Listening on http://{host}:{port}")
    print(f"[+] Dashboard  http://{'localhost' if settings.is_loopback else host}:{port}")
    print(f"[+] Audit log  {settings.audit_log_path}")
    if settings.console_telemetry:
        print("[+] Console telemetry enabled")
    else:
        print("[i] Console telemetry disabled (NOVAGATE_CONSOLE_TELEMETRY=0)")

    uvicorn.run(app, host=host, port=port, log_level=args.log_level)
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="novagate",
        description="NovaGate-AIShield - a transparent AI prompt firewall.",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    sub = parser.add_subparsers(dest="command")

    p_inspect = sub.add_parser("inspect", help="inspect a single prompt")
    p_inspect.add_argument("prompt")
    p_inspect.add_argument("--json", action="store_true", help="machine-readable output")
    p_inspect.set_defaults(func=cmd_inspect)

    p_scan = sub.add_parser("scan", help="inspect each line of a file")
    p_scan.add_argument("-f", "--file", required=True)
    p_scan.add_argument("--json", action="store_true")
    p_scan.set_defaults(func=cmd_scan)

    p_cat = sub.add_parser("categories", help="list the detection catalog")
    p_cat.set_defaults(func=cmd_categories)

    p_serve = sub.add_parser("serve", help="run the HTTP gateway")
    p_serve.add_argument("--host", default=None)
    p_serve.add_argument("--port", type=int, default=None)
    p_serve.add_argument("--log-level", default="info")
    p_serve.set_defaults(func=cmd_serve)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if not getattr(args, "command", None):
        parser.print_help()
        return 1
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
