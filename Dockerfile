# Recupero worker image — used by Railway via railway.json's
# `builder: DOCKERFILE`. Nixpacks' default Python flow copies only
# pyproject.toml before running `pip install .`, which breaks our
# src-layout project (setuptools can't find the `src/` dir at install
# time). This Dockerfile copies every needed file before installing.

FROM python:3.12-slim

WORKDIR /app

# All wheels we need ship pre-built for cp312-manylinux (psycopg[binary],
# pydantic-core, orjson, pycryptodome, pyyaml). No compiler needed.
# ca-certificates is in the slim base; nothing else to install at the OS
# level for now.

# Install Python deps. Order is set up so that adding a code-only change
# doesn't bust the dep-install cache layer.
COPY pyproject.toml README.md ./
COPY src/ ./src/
COPY config/ ./config/

# Editable install (`-e`). Reason: src/recupero/config.py looks up
# config/default.yaml via `Path(__file__).parents[2] / "config" / ...`.
# A normal install puts __file__ in site-packages so parents[2] points
# to /usr/local/lib/python3.12/ (wrong). Editable keeps __file__ in
# /app/src/recupero/, so parents[2] = /app and /app/config/ resolves.
# A future refactor of config.py to use importlib.resources would let
# us go back to a regular install.
RUN pip install --no-cache-dir --upgrade pip setuptools wheel && \
    pip install --no-cache-dir -e .

# `recupero-worker` is registered by pyproject.toml's [project.scripts].
# railway.json's startCommand also points here; both end up the same.
CMD ["recupero-worker"]
