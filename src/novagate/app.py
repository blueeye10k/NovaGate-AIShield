"""FastAPI application: the HTTP shield layer."""

from __future__ import annotations

import asyncio
import logging
import re
import secrets
import time
from pathlib import Path
from typing import Any

from fastapi import Depends, FastAPI, Header, HTTPException, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, JSONResponse, Response
from pydantic import BaseModel, Field

from novagate.audit import AuditLogger
from novagate.config import Settings
from novagate.config import settings as global_settings
from novagate.evaluator import VectorThreatEvaluator
from novagate.normalizer import AdvancedPayloadNormalizer, NormalizationReport
from novagate.ratelimit import RateLimitDecision, SlidingWindowRateLimiter
from novagate.signatures import CATEGORIES

logger = logging.getLogger("novagate")

# Request IDs are trace IDs, not user data: hex, dashes and dots only.
_SAFE_REQUEST_ID_RE = re.compile(r"[A-Za-z0-9._:-]{1,64}")

TEMPLATES_DIR = Path(__file__).parent / "templates"

# Uniform error codes so clients never have to parse prose.
THREAT_MALFORMED = "MALFORMED_PAYLOAD"
THREAT_BLOCKED = "SECURITY_ACCESS_VIOLATION"
THREAT_STRUCTURAL = "ANOMALOUS_PAYLOAD_STRUCTURE"
THREAT_TOO_LARGE = "PAYLOAD_TOO_LARGE"
THREAT_RATE_LIMITED = "RATE_LIMIT_EXCEEDED"
THREAT_UNAUTHORIZED = "INVALID_CREDENTIALS"


class PromptPayload(BaseModel):
    """Inspection request body."""

    user_prompt: str = Field(..., description="Untrusted user input to inspect")
    # v2 rejected anything over 10 000 chars with a bare 422 from pydantic and a
    # confusing message. Oversized input is now an explicit, documented error.
    model_config = {"extra": "forbid"}

    def validated_length(self, limit: int) -> str | None:
        return None if len(self.user_prompt) <= limit else self.user_prompt


def _http_413() -> int:
    """Starlette renamed this constant; support both spellings."""
    return getattr(status, "HTTP_413_CONTENT_TOO_LARGE", 413)


def _error(
    status_code: int,
    code: str,
    message: str,
    request_id: str | None = None,
    headers: dict[str, str] | None = None,
    extra: dict[str, Any] | None = None,
) -> JSONResponse:
    """Build the uniform error envelope."""
    body: dict[str, Any] = {"status": code, "message": message}
    if request_id:
        body["request_id"] = request_id
    if extra:
        body.update(extra)
    return JSONResponse(status_code=status_code, content={"detail": body}, headers=headers or {})


class AppState:
    """Mutable runtime state, grouped so it can be swapped in tests."""

    def __init__(self, config: Settings) -> None:
        self.config = config
        self.normalizer = AdvancedPayloadNormalizer(config)
        self.evaluator = VectorThreatEvaluator(config)
        self.limiter = SlidingWindowRateLimiter(
            limit=config.rate_limit_requests, window=config.rate_limit_window
        )
        self.audit = AuditLogger(
            path=config.audit_log_path,
            enabled=config.audit_enabled,
            max_bytes=config.audit_max_bytes,
            backup_count=config.audit_backup_count,
            max_preview_chars=config.audit_max_preview_chars,
        )
        self.started_at = time.time()
        self.counters: dict[str, int] = {
            "requests_total": 0,
            "passed_total": 0,
            "blocked_total": 0,
            "review_total": 0,
            "rate_limited_total": 0,
            "errors_total": 0,
        }
        self.counter_lock = asyncio.Lock()

    def bump(self, name: str, amount: int = 1) -> None:
        self.counters[name] = self.counters.get(name, 0) + amount


def _request_id_from(supplied: str | None) -> str:
    """Accept a caller-supplied request ID, but only a sane one.

    The ID is echoed in a response header *and* written to every audit entry, so
    an unbounded client-supplied value is a log-volume amplifier: one request
    with a 4KB ``X-Request-ID`` wrote a 4KB line, and the caller chose the
    content. Anything that is not short and boring is replaced rather than
    trusted, which keeps correlation working without letting a client dictate
    what lands on disk.
    """
    if supplied and len(supplied) <= 64 and _SAFE_REQUEST_ID_RE.fullmatch(supplied):
        return supplied
    return secrets.token_hex(8)


def create_app(config: Settings | None = None) -> FastAPI:
    """Build the application. Exposed so tests can build isolated instances."""
    cfg = config or global_settings

    app = FastAPI(
        title="NovaGate-AIShield",
        version="3.0.0",
        description=(
            "A transparent AI prompt firewall. Inspects untrusted prompts before "
            "they reach a model and returns a structured verdict."
        ),
        # v2 served /docs and /openapi.json publicly with no auth, leaking the
        # full API surface. Off unless explicitly enabled.
        docs_url="/docs" if cfg.expose_docs else None,
        redoc_url="/redoc" if cfg.expose_docs else None,
        openapi_url="/openapi.json" if cfg.expose_docs else None,
    )
    app.state.novagate = AppState(cfg)

    if cfg.cors_origins:
        app.add_middleware(
            CORSMiddleware,
            allow_origins=list(cfg.cors_origins),
            allow_credentials=False,
            allow_methods=["GET", "POST"],
            allow_headers=["*"],
        )

    @app.middleware("http")
    async def request_context(request: Request, call_next):
        """Attach a request ID and rate-limit headers to every response."""
        request_id = _request_id_from(request.headers.get("X-Request-ID"))
        request.state.request_id = request_id
        st: AppState = app.state.novagate
        st.bump("requests_total")

        started = time.perf_counter()
        try:
            response = await call_next(request)
        except Exception:
            st.bump("errors_total")
            logger.exception("unhandled error request_id=%s", request_id)
            return _error(
                status.HTTP_500_INTERNAL_SERVER_ERROR,
                "INTERNAL_ERROR",
                "The request could not be processed.",
                request_id,
            )

        elapsed_ms = (time.perf_counter() - started) * 1000
        response.headers["X-Request-ID"] = request_id
        response.headers["X-Response-Time-ms"] = f"{elapsed_ms:.2f}"
        return response

    # ------------------------------------------------------------- helpers
    def client_identity(request: Request) -> str:
        """Identify the caller for rate limiting.

        ``X-Forwarded-For`` is only honoured when explicitly enabled. Trusting
        it by default lets any client spoof its way past the limiter by sending
        a random header.
        """
        if cfg.trust_forwarded_for:
            forwarded = request.headers.get("X-Forwarded-For", "")
            if forwarded:
                return forwarded.split(",")[0].strip()
        return request.client.host if request.client else "unknown"

    def require_auth(
        x_api_key: str | None = Header(default=None, alias="X-API-Key"),
        authorization: str | None = Header(default=None),
    ) -> None:
        """Enforce the API key when one is configured."""
        st: AppState = app.state.novagate
        if not (cfg.require_auth or cfg.api_key):
            return
        if not cfg.api_key:
            raise HTTPException(status_code=500, detail="API key misconfigured")
        provided = x_api_key
        if not provided and authorization and authorization.lower().startswith("bearer "):
            provided = authorization[7:]
        # Constant-time compare so the key cannot be recovered byte by byte.
        if not provided or not secrets.compare_digest(provided, cfg.api_key):
            st.bump("errors_total")
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail={
                    "status": THREAT_UNAUTHORIZED,
                    "message": "A valid X-API-Key header is required.",
                },
            )

    def enforce_bind_safety() -> None:
        """Refuse to expose an unauthenticated firewall on a public interface."""
        if not cfg.is_loopback and not cfg.api_key and not cfg.require_auth:
            raise RuntimeError(
                f"NovaGate is configured to bind {cfg.host} with no API key. "
                "Anyone who can reach this port can read the dashboard, the "
                "audit log and the detection internals. Set NOVAGATE_API_KEY, "
                "or bind 127.0.0.1 to use it locally."
            )

    if not cfg.is_loopback:
        enforce_bind_safety()

    async def render_console(
        raw: str, report: NormalizationReport, telemetry: dict, request_id: str
    ) -> None:
        """Render the rich triage table off the event loop.

        v2 called ``EnterpriseSOCDashboard.render_triage_packet`` directly from
        an ``async def`` handler. Rich writes to stdout synchronously, so every
        request blocked the event loop for the duration of the write -- a cheap
        DoS amplifier. Running it in the default executor keeps the loop free.
        """
        if not cfg.console_telemetry:
            return
        from novagate.console import render_triage_packet

        loop = asyncio.get_running_loop()
        await loop.run_in_executor(
            None, lambda: render_triage_packet(raw, report, telemetry, request_id)
        )

    # -------------------------------------------------------------- routes
    @app.get("/", response_class=HTMLResponse, include_in_schema=False)
    async def dashboard() -> HTMLResponse:
        template = TEMPLATES_DIR / "dashboard.html"
        try:
            return HTMLResponse(template.read_text(encoding="utf-8"))
        except FileNotFoundError:
            return HTMLResponse("<h1>Dashboard template missing</h1>", status_code=500)

    @app.get("/healthz", include_in_schema=False)
    async def healthz() -> dict:
        st: AppState = app.state.novagate
        return {
            "status": "ok",
            "uptime_seconds": round(time.time() - st.started_at, 1),
            "version": app.version,
        }

    @app.get("/api/v1/categories")
    async def categories(_: None = Depends(require_auth)) -> dict:
        """The full detection catalog -- what this tool can and cannot see."""
        return {
            "categories": [
                {
                    "name": category.name,
                    "description": category.description,
                    "base_criticality": category.base_criticality,
                    "hard_block": category.hard_block,
                    "signature_count": len(category.signatures),
                }
                for category in CATEGORIES
            ]
        }

    @app.get("/api/v1/stats", include_in_schema=False)
    async def stats(_: None = Depends(require_auth)) -> dict:
        st: AppState = app.state.novagate
        return {
            "counters": dict(st.counters),
            "tracked_clients": st.limiter.tracked_clients,
            "uptime_seconds": round(time.time() - st.started_at, 1),
        }

    @app.post("/api/v1/inspect")
    async def inspect(
        request: Request,
        payload: PromptPayload,
        _: None = Depends(require_auth),
    ):
        """Inspect one prompt. Returns 200 / 400 / 403 / 413 / 422 / 429."""
        st: AppState = app.state.novagate
        request_id = request.state.request_id

        # 1. Rate limiting (token bucket / sliding window).
        if cfg.rate_limit_enabled:
            decision: RateLimitDecision = st.limiter.check(client_identity(request))
            if not decision.allowed:
                st.bump("rate_limited_total")
                st.audit.record(
                    "rate_limited",
                    severity="WARNING",
                    client=client_identity(request),
                    request_id=request_id,
                    retry_after=round(decision.retry_after, 2),
                )
                return _error(
                    status.HTTP_429_TOO_MANY_REQUESTS,
                    THREAT_RATE_LIMITED,
                    "Too many requests. Slow down and try again.",
                    request_id,
                    headers=decision.headers(),
                )

        # 2. Size and emptiness. Pydantic bounds the body; check the field too.
        raw = payload.user_prompt
        if len(raw.encode("utf-8", "ignore")) > cfg.max_raw_bytes:
            st.bump("errors_total")
            return _error(
                _http_413(),
                THREAT_TOO_LARGE,
                f"Prompt exceeds the {cfg.max_raw_bytes} byte limit.",
                request_id,
            )
        if not raw.strip():
            st.bump("errors_total")
            st.audit.record(
                "malformed",
                severity="WARNING",
                client=client_identity(request),
                request_id=request_id,
            )
            return _error(
                status.HTTP_400_BAD_REQUEST,
                THREAT_MALFORMED,
                "user_prompt must contain at least one non-whitespace character.",
                request_id,
            )

        # 3. Normalise and evaluate.
        report = st.normalizer.execute_normalization_pipeline(raw)
        blocked, telemetry = st.evaluator.evaluate(report)

        await render_console(raw, report, telemetry, request_id)

        identity = client_identity(request)
        envelope = {
            "status": "PROCESSED_SUCCESSFULLY",
            "verdict": telemetry["verdict"],
            "risk_index": telemetry["calculated_risk_index"],
            "request_id": request_id,
            "normalization": report.to_dict(),
            "telemetry": telemetry,
        }

        if blocked:
            st.bump("blocked_total")
            st.audit.record(
                "threat_blocked",
                severity="CRITICAL",
                payload_preview=report.primary,
                payload_sha256=report.payload_sha256,
                client=identity,
                request_id=request_id,
                risk=telemetry["calculated_risk_index"],
                categories=telemetry["categories_triggered"],
                layers=report.layers_unwrapped,
            )
            return _error(
                status.HTTP_403_FORBIDDEN,
                THREAT_BLOCKED,
                "Prompt matched a security rule and was blocked.",
                request_id,
                extra={
                    "verdict": telemetry["verdict"],
                    "risk_index": telemetry["calculated_risk_index"],
                    "categories": telemetry["categories_triggered"],
                    "detail_telemetry": telemetry,
                },
            )

        if telemetry["needs_review"]:
            st.bump("review_total")

        # 4. Structural anomaly. v2 gated this on Shannon entropy >= 5.8, which
        # is unreachable -- entropy peaks near 4.9 even on base64 blobs, so the
        # branch never ran. This uses a score that can actually trigger.
        if telemetry["structural_anomaly"] >= cfg.structural_anomaly_threshold:
            st.bump("errors_total")
            st.audit.record(
                "structural_anomaly",
                severity="WARNING",
                payload_preview=report.primary,
                payload_sha256=report.payload_sha256,
                client=identity,
                request_id=request_id,
                structural=telemetry["structural_anomaly"],
            )
            return _error(
                status.HTTP_422_UNPROCESSABLE_ENTITY,
                THREAT_STRUCTURAL,
                "Payload structure is not consistent with human text.",
                request_id,
                extra={
                    "structural_anomaly": telemetry["structural_anomaly"],
                    "detail_telemetry": telemetry,
                },
            )

        st.bump("passed_total")
        st.audit.record(
            "prompt_passed",
            severity="INFO",
            payload_preview=report.primary,
            payload_sha256=report.payload_sha256,
            client=identity,
            request_id=request_id,
            risk=telemetry["calculated_risk_index"],
            verdict=telemetry["verdict"],
        )
        return envelope

    @app.post("/api/v1/chat/completions")
    async def chat_completions(
        request: Request,
        _: None = Depends(require_auth),
    ):
        """Pass-through proxy: inspect, then forward to the upstream provider.

        Optional. Requires ``NOVAGATE_UPSTREAM_URL``. Keeping the provider key on
        the server is the main reason to use this shape instead of calling the
        inspector from your own backend.
        """
        st: AppState = app.state.novagate
        request_id = request.state.request_id

        if not cfg.upstream_url:
            return _error(
                status.HTTP_501_NOT_IMPLEMENTED,
                "PROXY_DISABLED",
                "Pass-through is not configured. Set NOVAGATE_UPSTREAM_URL.",
                request_id,
            )

        # Rate limiting and size limits apply here too. This route is strictly
        # more expensive than /inspect -- it makes a network call and spends
        # someone's API credit -- so leaving it unthrottled would make the
        # limiter trivially bypassable by using the proxy route instead.
        if cfg.rate_limit_enabled:
            decision: RateLimitDecision = st.limiter.check(client_identity(request))
            if not decision.allowed:
                st.bump("rate_limited_total")
                st.audit.record(
                    "rate_limited",
                    severity="WARNING",
                    client=client_identity(request),
                    request_id=request_id,
                    retry_after=round(decision.retry_after, 2),
                    route="proxy",
                )
                return _error(
                    status.HTTP_429_TOO_MANY_REQUESTS,
                    THREAT_RATE_LIMITED,
                    "Too many requests. Slow down and try again.",
                    request_id,
                    headers=decision.headers(),
                )

        try:
            body = await request.json()
        except Exception:
            return _error(
                status.HTTP_400_BAD_REQUEST,
                THREAT_MALFORMED,
                "Request body must be valid JSON.",
                request_id,
            )

        messages = body.get("messages") or []
        if not isinstance(messages, list) or not messages:
            return _error(
                status.HTTP_400_BAD_REQUEST,
                THREAT_MALFORMED,
                "'messages' must be a non-empty array.",
                request_id,
            )

        # Inspect every user turn, and the concatenated whole for indirect
        # injection arriving inside a retrieved document.
        untrusted = "\n".join(
            str(m.get("content", ""))
            for m in messages
            if isinstance(m, dict) and m.get("role") in {"user", "tool"}
        )
        if not untrusted.strip():
            return _error(
                status.HTTP_400_BAD_REQUEST,
                THREAT_MALFORMED,
                "No user or tool messages to inspect.",
                request_id,
            )

        # The concatenated untrusted text is what we scan, so it is what has to
        # respect the size limit. Without this a caller could send an
        # arbitrarily large conversation, since each individual message stays
        # under max_raw_bytes while the concatenation does not.
        if len(untrusted.encode("utf-8", "ignore")) > cfg.max_raw_bytes:
            st.bump("errors_total")
            return _error(
                _http_413(),
                THREAT_TOO_LARGE,
                f"Conversation exceeds the {cfg.max_raw_bytes} byte limit.",
                request_id,
            )

        report = st.normalizer.execute_normalization_pipeline(untrusted)
        blocked, telemetry = st.evaluator.evaluate(report)

        if blocked:
            st.bump("blocked_total")
            st.audit.record(
                "proxy_threat_blocked",
                severity="CRITICAL",
                payload_preview=report.primary,
                payload_sha256=report.payload_sha256,
                client=client_identity(request),
                request_id=request_id,
                risk=telemetry["calculated_risk_index"],
                categories=telemetry["categories_triggered"],
            )
            return _error(
                status.HTTP_403_FORBIDDEN,
                THREAT_BLOCKED,
                "Request blocked before reaching the model.",
                request_id,
                extra={"categories": telemetry["categories_triggered"]},
            )

        st.bump("passed_total")
        headers = {"Content-Type": "application/json"}
        if cfg.upstream_api_key:
            headers["Authorization"] = f"Bearer {cfg.upstream_api_key}"

        try:
            import httpx

            async with httpx.AsyncClient(timeout=cfg.upstream_timeout) as client:
                upstream = await client.post(cfg.upstream_url, json=body, headers=headers)
        except Exception as exc:  # network failure must not leak internals
            st.bump("errors_total")
            logger.warning("upstream request failed: %s", type(exc).__name__)
            return _error(
                status.HTTP_502_BAD_GATEWAY,
                "UPSTREAM_UNAVAILABLE",
                "The upstream model provider could not be reached.",
                request_id,
            )

        return Response(
            content=upstream.content,
            status_code=upstream.status_code,
            media_type=upstream.headers.get("content-type", "application/json"),
        )

    return app


app = create_app()
