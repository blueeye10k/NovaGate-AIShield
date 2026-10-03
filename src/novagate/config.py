"""Central configuration.

Every tunable lives here and is overridable through environment variables so a
deployment can be tuned without editing code. Nothing in the detection engine
reads ``os.environ`` directly -- thresholds are passed in, which keeps the
engine pure and testable.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field, replace
from typing import Mapping


def _env_str(name: str, default: str) -> str:
    value = os.getenv(name)
    return default if value is None or value == "" else value


def _env_opt(name: str) -> str | None:
    value = os.getenv(name)
    return None if value is None or value == "" else value


def _env_int(name: str, default: int) -> int:
    raw = _env_opt(name)
    if raw is None:
        return default
    try:
        return int(raw)
    except ValueError:
        return default


def _env_float(name: str, default: float) -> float:
    raw = _env_opt(name)
    if raw is None:
        return default
    try:
        return float(raw)
    except ValueError:
        return default


def _env_bool(name: str, default: bool) -> bool:
    raw = _env_opt(name)
    if raw is None:
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


def _env_list(name: str, default: tuple[str, ...] = ()) -> tuple[str, ...]:
    raw = _env_opt(name)
    if raw is None:
        return default
    return tuple(item.strip() for item in raw.split(",") if item.strip())


@dataclass(frozen=True)
class Settings:
    """Immutable runtime settings.

    Use :meth:`evolve` to derive a modified copy in tests instead of mutating.
    """

    # --- network -------------------------------------------------------
    host: str = field(default_factory=lambda: _env_str("NOVAGATE_HOST", "127.0.0.1"))
    port: int = field(default_factory=lambda: _env_int("NOVAGATE_PORT", 8000))

    # --- authentication ------------------------------------------------
    # When the server is reachable from anything other than loopback this
    # becomes mandatory; see novagate.app._enforce_bind_safety.
    api_key: str | None = field(default_factory=lambda: _env_opt("NOVAGATE_API_KEY"))
    require_auth: bool = field(
        default_factory=lambda: _env_bool("NOVAGATE_REQUIRE_AUTH", False)
    )
    # Only honour X-Forwarded-For when you actually run behind a proxy you
    # control. Trusting it blindly lets a client spoof its way past rate limits.
    trust_forwarded_for: bool = field(
        default_factory=lambda: _env_bool("NOVAGATE_TRUST_FORWARDED_FOR", False)
    )
    expose_docs: bool = field(
        default_factory=lambda: _env_bool("NOVAGATE_EXPOSE_DOCS", False)
    )
    cors_origins: tuple[str, ...] = field(
        default_factory=lambda: _env_list("NOVAGATE_CORS_ORIGINS")
    )

    # --- request limits ------------------------------------------------
    max_prompt_chars: int = field(
        default_factory=lambda: _env_int("NOVAGATE_MAX_PROMPT_CHARS", 10000)
    )
    # Hard ceiling on input so a single request cannot burn CPU. Requests above
    # this are rejected outright rather than normalised.
    max_raw_bytes: int = field(
        default_factory=lambda: _env_int("NOVAGATE_MAX_RAW_BYTES", 64_000)
    )

    # --- normalisation -------------------------------------------------
    max_decode_passes: int = field(
        default_factory=lambda: _env_int("NOVAGATE_MAX_DECODE_PASSES", 6)
    )
    # Total decoded bytes across all layers. Bounds nested-encoding blowups.
    max_decoded_bytes: int = field(
        default_factory=lambda: _env_int("NOVAGATE_MAX_DECODED_BYTES", 200_000)
    )
    min_b64_run: int = field(
        default_factory=lambda: _env_int("NOVAGATE_MIN_B64_RUN", 16)
    )
    # Fraction of decoded characters that must be printable for a base64/hex
    # decode to be trusted. Binary noise is discarded instead of replacing the
    # payload (this is what made the original decoder bypassable).
    min_printable_ratio: float = field(
        default_factory=lambda: _env_float("NOVAGATE_MIN_PRINTABLE_RATIO", 0.90)
    )

    # --- detection thresholds -----------------------------------------
    block_threshold: float = field(
        default_factory=lambda: _env_float("NOVAGATE_BLOCK_THRESHOLD", 5.0)
    )
    review_threshold: float = field(
        default_factory=lambda: _env_float("NOVAGATE_REVIEW_THRESHOLD", 3.2)
    )
    structural_anomaly_threshold: float = field(
        default_factory=lambda: _env_float("NOVAGATE_STRUCTURAL_THRESHOLD", 0.90)
    )

    # --- rate limiting -------------------------------------------------
    rate_limit_enabled: bool = field(
        default_factory=lambda: _env_bool("NOVAGATE_RATE_LIMIT_ENABLED", True)
    )
    rate_limit_requests: int = field(
        default_factory=lambda: _env_int("NOVAGATE_RATE_LIMIT_REQUESTS", 30)
    )
    rate_limit_window: float = field(
        default_factory=lambda: _env_float("NOVAGATE_RATE_LIMIT_WINDOW", 60.0)
    )

    # --- audit log -----------------------------------------------------
    audit_log_path: str = field(
        default_factory=lambda: _env_str("NOVAGATE_AUDIT_LOG", "security_audit.log")
    )
    audit_enabled: bool = field(
        default_factory=lambda: _env_bool("NOVAGATE_AUDIT_ENABLED", True)
    )
    audit_max_bytes: int = field(
        default_factory=lambda: _env_int("NOVAGATE_AUDIT_MAX_BYTES", 10_000_000)
    )
    audit_backup_count: int = field(
        default_factory=lambda: _env_int("NOVAGATE_AUDIT_BACKUP_COUNT", 5)
    )
    audit_max_preview_chars: int = field(
        default_factory=lambda: _env_int("NOVAGATE_AUDIT_PREVIEW_CHARS", 120)
    )

    # --- pass-through proxy (optional) ---------------------------------
    upstream_url: str | None = field(
        default_factory=lambda: _env_opt("NOVAGATE_UPSTREAM_URL")
    )
    upstream_api_key: str | None = field(
        default_factory=lambda: _env_opt("NOVAGATE_UPSTREAM_API_KEY")
    )
    upstream_timeout: float = field(
        default_factory=lambda: _env_float("NOVAGATE_UPSTREAM_TIMEOUT", 30.0)
    )

    # --- console telemetry ---------------------------------------------
    console_telemetry: bool = field(
        default_factory=lambda: _env_bool("NOVAGATE_CONSOLE_TELEMETRY", True)
    )

    def evolve(self, **overrides) -> "Settings":
        """Return a copy with ``overrides`` applied."""
        return replace(self, **overrides)

    @property
    def is_loopback(self) -> bool:
        return self.host in {"127.0.0.1", "::1", "localhost"}


settings = Settings()


def get_settings() -> Settings:
    """FastAPI dependency hook."""
    return settings
