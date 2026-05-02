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
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        graphviz \
        fonts-dejavu-core \
        ca-certificates && \
    rm -rf /var/lib/apt/lists/*

# Install Python deps. Order is set up so that adding a code-only change
# doesn't bust the dep-install cache layer.
COPY pyproject.toml README.md ./
COPY src/ ./src/

# Regular install. config.py reads default.yaml via importlib.resources
# from the bundled `recupero._defaults` package, so we don't need to
# COPY config/ or use editable install anymore.
RUN pip install --no-cache-dir --upgrade pip setuptools wheel && \
    pip install --no-cache-dir .

# `recupero-worker` is registered by pyproject.toml's [project.scripts].
# railway.json's startCommand also points here; both end up the same.
CMD ["recupero-worker"]
