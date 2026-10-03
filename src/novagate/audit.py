"""Structured, tamper-resistant audit logging.

v2 wrote free-text lines built by string interpolation::

    logging.critical(f"IP={client_ip} ... EXTRACTED='{norm_report['processed_string']}'")

That had three consequences worth fixing:

1. **Log injection.** Newlines in the attacker-controlled payload were written
   verbatim, so a payload could forge audit entries that looked legitimate.
2. **Unbounded growth.** A plain ``FileHandler`` never rotated.
3. **Secret retention.** The full decoded prompt was persisted, including any
   credentials a user pasted.

Entries are now single-line JSON, which escapes newlines by construction, are
size-capped, rotated, and store a *hash* plus a short redacted preview rather
than the full payload.
"""

from __future__ import annotations

import json
import logging
import os
import re
import threading
from dataclasses import dataclass
from logging.handlers import RotatingFileHandler
from typing import Any

# Patterns whose values must never reach disk.
_REDACTIONS: tuple[tuple[re.Pattern, str], ...] = (
    (re.compile(r"\b(sk-[A-Za-z0-9_\-]{12,})"), "sk-***"),
    (re.compile(r"\b(gh[pousr]_[A-Za-z0-9]{16,})"), "gh*_***"),
    (re.compile(r"\b(AKIA[0-9A-Z]{16})"), "AKIA***"),
    (re.compile(r"\b(xox[baprs]-[A-Za-z0-9-]{10,})"), "xox*-***"),
    (
        re.compile(
            r"(?i)\b(password|passwd|secret|api[_-]?key|token|authorization)\b(\s*[:=]\s*)(\S+)"
        ),
        r"\1\2***",
    ),
    (
        re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----"),
        "***PRIVATE KEY REDACTED***",
    ),
)


def redact(text: str) -> str:
    """Strip credential-shaped substrings from ``text``."""
    for pattern, replacement in _REDACTIONS:
        text = pattern.sub(replacement, text)
    # Control characters would let a payload forge a line break.
    return re.sub(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]", " ", text)


@dataclass
class AuditLogger:
    """Append-only JSON-lines audit log with rotation."""

    path: str = "security_audit.log"
    enabled: bool = True
    max_bytes: int = 10_000_000
    backup_count: int = 5
    max_preview_chars: int = 120

    def __post_init__(self) -> None:
        self._lock = threading.Lock()
        self._logger: logging.Logger | None = None
        if not self.enabled:
            return

        logger = logging.getLogger("novagate.audit")
        logger.setLevel(logging.INFO)
        logger.propagate = False
        # Replace handlers so repeated construction (tests, reload) does not
        # duplicate every line.
        for handler in list(logger.handlers):
            logger.removeHandler(handler)
            handler.close()

        directory = os.path.dirname(os.path.abspath(self.path))
        if directory:
            os.makedirs(directory, exist_ok=True)

        handler = RotatingFileHandler(
            self.path,
            maxBytes=self.max_bytes,
            backupCount=self.backup_count,
            encoding="utf-8",
        )
        # The handler emits raw JSON; adding a prefix would corrupt the format.
        handler.setFormatter(logging.Formatter("%(message)s"))
        logger.addHandler(handler)
        self._logger = logger

    # ------------------------------------------------------------------ api
    def preview(self, text: str) -> str:
        return redact(text)[: self.max_preview_chars]

    def record(
        self,
        event: str,
        *,
        severity: str = "INFO",
        payload_preview: str | None = None,
        payload_sha256: str | None = None,
        **fields: Any,
    ) -> dict:
        """Write one audit entry and return it.

        Always returns the entry even when logging is disabled, so tests and
        the HTTP response can both use it.
        """
        entry: dict[str, Any] = {"event": event, "severity": severity}
        if payload_preview is not None:
            entry["payload_preview"] = self.preview(payload_preview)
            entry["payload_truncated"] = len(payload_preview) > self.max_preview_chars
        if payload_sha256 is not None:
            entry["payload_sha256"] = payload_sha256
        for key, value in fields.items():
            if isinstance(value, (str, int, float, bool, type(None), list, dict)):
                entry[key] = value

        if self._logger is not None:
            with self._lock:
                # json.dumps escapes newlines, so a hostile payload cannot forge
                # an extra log line.
                self._logger.log(
                    getattr(logging, severity.upper(), logging.INFO),
                    json.dumps(entry, ensure_ascii=True, default=str),
                )
        return entry

    def close(self) -> None:
        logger = logging.getLogger("novagate.audit")
        for handler in list(logger.handlers):
            logger.removeHandler(handler)
            handler.close()
        self._logger = None


# Process-wide default. Reconfigured by novagate.app during startup.
audit_logger = AuditLogger()
