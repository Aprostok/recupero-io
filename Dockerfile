# Recupero worker image — used by Railway via railway.json's
# `builder: DOCKERFILE`. Nixpacks' default Python flow copies only
# pyproject.toml before running `pip install .`, which breaks our
# src-layout project (setuptools can't find the `src/` dir at install
# time). This Dockerfile copies every needed file before installing.

FROM python:3.12-slim

WORKDIR /app

# All Python wheels we need ship pre-built for cp312-manylinux
# (psycopg[binary], pydantic-core, orjson, pycryptodome, pyyaml).
#
# System deps:
#   - graphviz: layout/rendering binary (`dot`) for flow diagrams in
#     the freeze-request + LE handoff HTMLs. The Python `graphviz`
#     package is a thin wrapper around the binary.
#   - fonts-dejavu-core: clean sans-serif fallback so nodes/labels
#     don't render in the awful default bitmap font.
#   - WeasyPrint runtime libs (libpango / libcairo / libgdk-pixbuf / libffi /
#     shared-mime-info): generate PDF versions of every freeze letter
#     and LE handoff in the building_package stage. ~80MB image-size
#     overhead; needed because PDFs are the deliverable format
#     compliance teams expect.
#   - fonts-liberation: serif/sans/mono fallbacks the letterhead uses
#     when no system Georgia is present; WeasyPrint embeds these into
#     the PDF for cross-reader consistency.
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        graphviz \
        fonts-dejavu-core \
        fonts-liberation \
        ca-certificates \
        libpango-1.0-0 \
        libpangoft2-1.0-0 \
        libcairo2 \
        libgdk-pixbuf-2.0-0 \
        libffi8 \
        shared-mime-info && \
    rm -rf /var/lib/apt/lists/*

# Create the unprivileged runtime user up front so the COPY layers below
# can land with the right ownership instead of needing a recursive chown
# pass at the end (which would double the image size for /app).
RUN useradd -m -u 10001 recupero

# Install Python deps. Order is set up so that adding a code-only change
# doesn't bust the dep-install cache layer.
COPY --chown=recupero:recupero pyproject.toml README.md ./
COPY --chown=recupero:recupero src/ ./src/

# Regular install. config.py reads default.yaml via importlib.resources
# from the bundled `recupero._defaults` package, so we don't need to
# COPY config/ or use editable install anymore.
RUN pip install --no-cache-dir --upgrade pip setuptools wheel && \
    pip install --no-cache-dir . && \
    chown -R recupero:recupero /app

# Drop privileges before running the worker. W12-05: containers should
# never run as root in production.
USER recupero

# Health server (recupero.worker._health_server) binds $PORT or 8080 and
# serves GET /healthz (liveness) + GET /health (readiness). railway.json
# points `healthcheckPath` at /healthz, so EXPOSE + a HEALTHCHECK
# directive let the image self-report and let Railway / `docker inspect`
# surface a regression (port not bound, server thread crashed) the
# moment it happens, instead of waiting for the Railway edge probe to
# notice. Probe budget fits inside railway.json's `healthcheckTimeout`.
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=10s --start-period=30s --retries=3 \
    CMD python -c "import os,urllib.request,sys; url=f'http://127.0.0.1:{os.environ.get(\"PORT\",\"8080\")}/healthz'; sys.exit(0 if urllib.request.urlopen(url, timeout=5).status==200 else 1)" || exit 1

# `recupero-api` is registered by pyproject.toml's [project.scripts]; it runs
# the FastAPI app (operator console /v1/console + /v1 API) and serves /healthz
# (alias of /v1/health) on $PORT, so the HEALTHCHECK + railway.json
# healthcheckPath above both pass. Kept ALIGNED with railway.json's
# startCommand (tests/test_deploy_config_audit.py enforces it). The background
# worker + cron run as separate Railway services that override startCommand to
# `recupero-worker` / `recupero-cron`.
CMD ["recupero-api"]
