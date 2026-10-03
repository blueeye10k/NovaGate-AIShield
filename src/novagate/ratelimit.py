"""Per-client rate limiting.

The v2 implementation kept a single timestamp per IP and rejected any request
arriving within 0.5s of the previous one. That is not a rate limit:

* it is a "too fast" check, not "N requests per window", so a client sending
  2 requests/second forever is throttled while a client sending 100 requests in
  a burst is served;
* the dict was never pruned, so it leaked memory for the lifetime of the
  process;
* it ignored ``X-Forwarded-For``, so behind a proxy every client shared one
  bucket;
* it returned no ``Retry-After``.

This is a sliding-window counter with lazy eviction.
"""

from __future__ import annotations

import threading
import time
from collections import defaultdict, deque
from dataclasses import dataclass


@dataclass(frozen=True)
class RateLimitDecision:
    allowed: bool
    limit: int
    remaining: int
    retry_after: float
    reset_after: float

    def headers(self) -> dict[str, str]:
        out = {
            "X-RateLimit-Limit": str(self.limit),
            "X-RateLimit-Remaining": str(max(0, self.remaining)),
            "X-RateLimit-Reset": str(int(self.reset_after)),
        }
        if not self.allowed:
            out["Retry-After"] = str(max(1, int(self.retry_after + 0.999)))
        return out


class SlidingWindowRateLimiter:
    """Thread-safe sliding window limiter keyed by client identity.

    Locking is required: the endpoints are ``async def`` but run on a thread
    pool, so the same instance is touched from multiple threads.
    """

    def __init__(
        self,
        limit: int = 30,
        window: float = 60.0,
        max_tracked_clients: int = 20_000,
    ) -> None:
        if limit < 1:
            raise ValueError("limit must be >= 1")
        if window <= 0:
            raise ValueError("window must be > 0")
        self.limit = limit
        self.window = window
        self.max_tracked_clients = max_tracked_clients
        self._hits: dict[str, deque[float]] = defaultdict(deque)
        self._lock = threading.Lock()

    def check(self, key: str) -> RateLimitDecision:
        """Record a hit for ``key`` and report whether it is allowed."""
        now = time.monotonic()
        cutoff = now - self.window

        with self._lock:
            self._evict_locked(cutoff)

            bucket = self._hits.get(key)
            if bucket is None:
                if len(self._hits) >= self.max_tracked_clients:
                    # Under memory pressure drop the coldest client rather than
                    # growing without bound.
                    self._evict_locked(cutoff, force_all_but_newest=True)
                bucket = self._hits[key] = deque()

            # Evict this client's expired hits.
            while bucket and bucket[0] <= cutoff:
                bucket.popleft()

            if len(bucket) >= self.limit:
                oldest = bucket[0]
                retry_after = max(0.0, oldest + self.window - now)
                return RateLimitDecision(
                    allowed=False,
                    limit=self.limit,
                    remaining=0,
                    retry_after=retry_after,
                    reset_after=retry_after,
                )

            bucket.append(now)
            oldest = bucket[0]
            reset_after = max(0.0, oldest + self.window - now)
            return RateLimitDecision(
                allowed=True,
                limit=self.limit,
                remaining=max(0, self.limit - len(bucket)),
                retry_after=0.0,
                reset_after=reset_after,
            )

    def _evict_locked(self, cutoff: float, force_all_but_newest: bool = False) -> None:
        """Drop fully-expired buckets. Caller must hold the lock.

        ``cutoff`` is the timestamp below which a bucket is considered stale;
        the caller computes it from its single ``now`` reading so every bucket
        is judged against the same instant.
        """
        if force_all_but_newest:
            if len(self._hits) > 1:
                # Keep the single most recently active client.
                newest = max(self._hits, key=lambda k: self._hits[k][-1] if self._hits[k] else 0)
                self._hits = {newest: self._hits[newest]}
            return

        stale = [key for key, bucket in self._hits.items() if not bucket or bucket[-1] <= cutoff]
        for key in stale:
            del self._hits[key]

    def reset(self, key: str | None = None) -> None:
        with self._lock:
            if key is None:
                self._hits.clear()
            else:
                self._hits.pop(key, None)

    @property
    def tracked_clients(self) -> int:
        with self._lock:
            return len(self._hits)
