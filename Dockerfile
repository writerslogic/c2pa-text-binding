# syntax=docker/dockerfile:1
# Reproducible Linux environment for the Tier 1 transport-survivability harness.
# Pins the Rust toolchain, the Debian transport tools (pandoc, tidy, iconv via
# glibc), and the Python sanitizer libraries. macOS-only transports (textutil)
# are absent by design here and are reported as skipped; run those natively.
#
#   docker build -t c2pa-transport .
#   docker run --rm c2pa-transport            # Tier 1 matrix
#   docker run --rm c2pa-transport \
#       cargo run -q --release --example transport_survivability   # Tier 0
FROM rust:1-slim-bookworm

RUN apt-get update && apt-get install -y --no-install-recommends \
        pandoc \
        tidy \
        python3 \
        python3-venv \
        ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY . .

RUN cargo build --release --example transport_survivability \
    && python3 -m venv harness/.venv \
    && harness/.venv/bin/pip install --no-cache-dir -r harness/requirements.txt

CMD ["harness/.venv/bin/python", "harness/tier1.py"]
