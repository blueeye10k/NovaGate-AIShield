# NovaGate-AIShield
#
# Two stages so the test dependencies are not present in the runtime image.
FROM python:3.12-slim AS builder

ENV PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /build
COPY requirements.txt requirements-dev.txt ./
COPY pyproject.toml README.md LICENSE ./
COPY src ./src

RUN python -m venv /opt/venv \
 && /opt/venv/bin/pip install --upgrade pip \
 && /opt/venv/bin/pip install -r requirements-dev.txt \
 && /opt/venv/bin/pip install --no-deps -e .


FROM python:3.12-slim AS runtime

LABEL org.opencontainers.image.title="NovaGate-AIShield" \
      org.opencontainers.image.description="A transparent AI prompt firewall" \
      org.opencontainers.image.source="https://github.com/blueeye10k/NovaGate-AIShield" \
      org.opencontainers.image.licenses="MIT"

# Run as an unprivileged user. The audit log lives on a mounted volume, so the
# logs directory is created and handed to the app user.
RUN groupadd --system --gid 1001 novagate \
 && useradd  --system --uid 1001 --gid novagate --no-create-home novagate

COPY --from=builder /opt/venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH" \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    NOVAGATE_HOST=0.0.0.0 \
    NOVAGATE_PORT=8000 \
    NOVAGATE_AUDIT_LOG=/var/log/novagate/security_audit.log \
    NOVAGATE_CONSOLE_TELEMETRY=false

RUN mkdir -p /var/log/novagate && chown -R novagate:novagate /var/log/novagate

WORKDIR /app
COPY --chown=novagate:novagate src ./src
COPY --chown=novagate:novagate pyproject.toml README.md LICENSE ./

USER novagate
EXPOSE 8000

# Loopback inside the container, so publishing the port is what exposes it.
# The bind-safety check in novagate.config requires an API key here; set
# NOVAGATE_API_KEY or the container will refuse to start.
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD python -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8000/healthz', timeout=2).status==200 else 1)"

CMD ["novagate", "serve", "--host", "0.0.0.0", "--port", "8000"]
