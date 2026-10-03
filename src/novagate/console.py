"""Rich console telemetry rendering."""

from __future__ import annotations

from datetime import datetime

from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from novagate.normalizer import NormalizationReport

_console = Console()


def get_console() -> Console:
    return _console


def print_gateway_header(version: str = "3.0.0") -> None:
    """Print the startup banner."""
    _console.print(
        Panel.fit(
            f"[bold cyan]NOVAGATE-AISHIELD[/bold cyan] : "
            f"[bold white]AI PROMPT FIREWALL v{version}[/bold white]",
            subtitle="Inline inspection gateway",
            border_style="cyan",
        )
    )


def render_triage_packet(
    raw_payload: str,
    normalization: NormalizationReport,
    metrics: dict,
    request_id: str = "",
) -> None:
    """Render one inspection decision.

    Every value goes through Rich markup escaping or plain text. v2 interpolated
    the attacker-controlled payload straight into a markup string, so a prompt
    containing ``[red]`` or ``[/]`` could corrupt or spoof the operator's view
    of the console.
    """
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]

    table = Table(
        title=f"SECURITY INSPECTION - {timestamp}",
        title_style="bold yellow",
        show_lines=False,
        expand=False,
    )
    table.add_column("Field", style="cyan", no_wrap=True)
    table.add_column("Value", overflow="fold")

    from rich.text import Text

    table.add_row("Request ID", Text(request_id or "-", style="dim"))
    table.add_row(
        "Ingested payload",
        Text(raw_payload[:90] + ("..." if len(raw_payload) > 90 else ""), style="dim"),
    )
    table.add_row(
        "Decoded text",
        Text(normalization.primary[:90] + ("..." if len(normalization.primary) > 90 else "")),
    )
    table.add_row(
        "Obfuscation layers",
        Text(
            ", ".join(normalization.layers_unwrapped) if normalization.layers_unwrapped else "none"
        ),
    )
    table.add_row("Shannon entropy", Text(f"{metrics.get('entropy_score', 0.0)} bits/char"))
    table.add_row("Structural anomaly", Text(str(metrics.get("structural_anomaly", 0.0))))
    table.add_row("Repetition ratio", Text(str(metrics.get("repetition_ratio", 0.0))))

    risk = metrics.get("calculated_risk_index", 0.0)
    block_at = metrics.get("thresholds", {}).get("block", 5.0)
    if risk >= block_at:
        risk_style, risk_text = "bold red", "BLOCKED"
    elif metrics.get("needs_review"):
        risk_style, risk_text = "bold yellow", "REVIEW"
    else:
        risk_style, risk_text = "bold green", "PASS"
    table.add_row(
        "Risk index",
        Text.assemble((f"{risk} / 10.0  ", risk_style), (risk_text, risk_style)),
    )

    categories = metrics.get("categories_triggered") or []
    table.add_row(
        "Categories",
        Text(", ".join(categories) if categories else "none", style="magenta"),
    )

    verdict = metrics.get("verdict", "PASS")
    badge = {
        "REJECT": "[bold white on red] BLOCKED [/bold white on red]",
        "REVIEW": "[bold black on yellow] REVIEW - LOG AND WATCH [/bold black on yellow]",
        "PASS": "[bold black on green] PASSED [/bold black on green]",
    }.get(verdict, verdict)
    table.add_row("Verdict", badge)

    _console.print(table)


# v2-compatible alias.
class EnterpriseSOCDashboard:
    """Backwards-compatible shim for the v2 import path."""

    @staticmethod
    def print_gateway_header() -> None:
        print_gateway_header()

    @staticmethod
    def render_triage_packet(
        raw_payload: str, normalization: dict, metrics: dict, request_id: str = ""
    ) -> None:
        """Accepts the v2 dict shape as well as a NormalizationReport."""
        from novagate.normalizer import normalize

        report = (
            normalization
            if isinstance(normalization, NormalizationReport)
            else normalize(raw_payload)
        )
        render_triage_packet(raw_payload, report, metrics, request_id)
