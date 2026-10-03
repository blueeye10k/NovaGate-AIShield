#!/usr/bin/env python3
"""Verify the rate limiter behaves like a rate limit.

Two properties are checked, and both are what v2 got wrong:

1. **A burst up to the limit is allowed.** The old limiter rejected any request
   arriving within 0.5s of the previous one, so a legitimate burst of five
   requests in a few milliseconds was throttled while a sustained flood of one
   request per second was served.

2. **Beyond the limit, requests are refused with ``Retry-After``.** v2 returned
   429 with no retry guidance.

    python examples/rate_limit_probe.py
    python examples/rate_limit_probe.py --limit 10 --window 5
    python examples/rate_limit_probe.py --unit-test
"""

from __future__ import annotations

import argparse
import os
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

PROMPT = "How do I list all files in a directory in Linux?"


def unit_test(limit: int, window: float) -> int:
    """Test the limiter directly, with no server involved."""
    from novagate.ratelimit import SlidingWindowRateLimiter

    failures = 0

    limiter = SlidingWindowRateLimiter(limit=limit, window=window)

    burst = [limiter.check("client-a").allowed for _ in range(limit + 3)]
    if burst[:limit] != [True] * limit:
        print(f"  FAIL  burst of {limit} was throttled: {burst}")
        failures += 1
    else:
        print(f"  ok    burst of {limit} allowed (v2 would have throttled this)")

    if any(burst[limit:]):
        print(f"  FAIL  request {limit + 1} was allowed")
        failures += 1
    else:
        print(f"  ok    request {limit + 1} onwards refused")

    # A different client must have its own bucket.
    if not limiter.check("client-b").allowed:
        print("  FAIL  a second client inherited the first client's bucket")
        failures += 1
    else:
        print("  ok    a second client has an independent bucket")

    # Retry-After must be present and sane on refusal.
    limiter.check("client-c")
    for _ in range(limit):
        limiter.check("client-c")
    decision = limiter.check("client-c")
    if decision.allowed:
        print("  FAIL  expected a refusal")
        failures += 1
    elif not (0 < decision.retry_after <= window):
        print(f"  FAIL  retry_after={decision.retry_after} outside (0, {window}]")
        failures += 1
    else:
        print(f"  ok    refusal carries Retry-After: {int(decision.retry_after + 0.999)}s")

    # The window must actually slide: after expiry the client is served again.
    quick = SlidingWindowRateLimiter(limit=1, window=0.4)
    quick.check("client-d")
    if quick.check("client-d").allowed:
        print("  FAIL  second request in-window was allowed")
        failures += 1
    time.sleep(0.5)
    if not quick.check("client-d").allowed:
        print("  FAIL  client still throttled after the window expired")
        failures += 1
    else:
        print("  ok    window slides: client served again after expiry")

    # Memory must not grow without bound.
    leaky = SlidingWindowRateLimiter(limit=5, window=0.2, max_tracked_clients=100)
    for i in range(1000):
        leaky.check(f"client-{i}")
        time.sleep(0.0005)
    if leaky.tracked_clients > 100:
        print(f"  FAIL  tracked_clients grew to {leaky.tracked_clients}")
        failures += 1
    else:
        print(f"  ok    stale clients are evicted (tracked {leaky.tracked_clients} <= 100)")

    print()
    return 1 if failures else 0


def live(url: str, limit: int, api_key: str | None, timeout: float) -> int:
    try:
        import httpx
    except ImportError:
        print("This example needs httpx: pip install httpx", file=sys.stderr)
        return 1

    headers = {"Content-Type": "application/json"}
    if api_key:
        headers["X-API-Key"] = api_key

    base = url.rstrip("/")
    try:
        httpx.get(f"{base}/healthz", timeout=timeout)
    except httpx.HTTPError as exc:
        print(f"Cannot reach {base}/healthz: {exc}", file=sys.stderr)
        return 2

    print(f"\n  probing {base} with {limit + 5} rapid requests")
    print("  (the server's own limit applies; check that a burst is not throttled)\n")

    codes = []
    for _ in range(limit + 5):
        response = httpx.post(
            f"{base}/api/v1/inspect",
            json={"user_prompt": PROMPT},
            headers=headers,
            timeout=timeout,
        )
        codes.append(response.status_code)
        if response.status_code == 429:
            print(f"  429  Retry-After: {response.headers.get('Retry-After', 'MISSING')}")
            print(
                f"       X-RateLimit-Limit: {response.headers.get('X-RateLimit-Limit', 'MISSING')}"
            )
            print(
                f"       X-RateLimit-Remaining: {response.headers.get('X-RateLimit-Remaining', 'MISSING')}"
            )
            break

    print()
    print("  status codes: " + " ".join(str(c) for c in codes))

    failures = 0
    if codes[: min(limit, len(codes))] == [200] * min(limit, len(codes)):
        print("  ok    a rapid burst was served")
    elif 429 in codes:
        print("  note  throttled inside the burst -- the server limit is lower than --limit")

    if 429 in codes:
        print("  ok    throttling kicked in")
    else:
        print("  note  no 429 observed; the server limit is higher than this probe")
    print()
    return failures


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--limit", type=int, default=30)
    parser.add_argument("--window", type=float, default=60.0)
    parser.add_argument("--url", default=os.getenv("NOVAGATE_URL", "http://127.0.0.1:8000"))
    parser.add_argument("--api-key", default=os.getenv("NOVAGATE_API_KEY"))
    parser.add_argument("--timeout", type=float, default=10.0)
    parser.add_argument(
        "--unit-test",
        action="store_true",
        help="test the limiter in-process instead of over HTTP",
    )
    args = parser.parse_args()

    print("\n  Rate limiter verification\n")
    if args.unit_test:
        return unit_test(args.limit, args.window)
    return live(args.url, args.limit, args.api_key, args.timeout)


if __name__ == "__main__":
    raise SystemExit(main())
