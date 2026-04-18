# chorgly — multi-stage Docker image
#
# Stage 1: Build the WASM frontend (wasm-pack).
# Stage 2: Build the native backend + admin binaries.
# Stage 3: Runtime — copies binaries and static files into a minimal image.
#
# Mounts expected at runtime:
#   /config  (read-only)  — reserved for future config file support
#   /data    (read-write) — CBOR database and auto-committed git repo
#
# Environment variables:
#   CHORGLY_PORT        (default 8080)
#   CHORGLY_DATA        (default /data)
#   CHORGLY_STATIC_DIR  (default /app/static)

# ---------------------------------------------------------------------------
# Stage 1: WASM frontend
# ---------------------------------------------------------------------------
FROM rust:slim AS wasm-builder

RUN apt-get update && apt-get install -y --no-install-recommends \
    curl ca-certificates \
  && rm -rf /var/lib/apt/lists/*

# Install wasm-pack.
RUN curl https://rustwasm.github.io/wasm-pack/installer/init.sh -sSf | sh

# Add the wasm32 target.
RUN rustup target add wasm32-unknown-unknown

WORKDIR /build

# Copy only the files needed for the frontend crate (+ shared core).
COPY Cargo.toml Cargo.lock ./
COPY src/core src/core
COPY src/frontend src/frontend
# Stub out other workspace members so the lock file resolves.
RUN mkdir -p src/backend/src && \
    printf '[package]\nname="chorgly-backend"\nversion="0.1.0"\nedition="2021"\n[[bin]]\nname="chorgly-backend"\npath="src/main.rs"\n' > src/backend/Cargo.toml && \
    printf 'fn main(){}' > src/backend/src/main.rs
RUN mkdir -p tools/admin/src && \
    printf '[package]\nname="chorgly-admin"\nversion="0.1.0"\nedition="2021"\n[[bin]]\nname="chorgly-admin"\npath="src/main.rs"\n' > tools/admin/Cargo.toml && \
    printf 'fn main(){}' > tools/admin/src/main.rs

RUN wasm-pack build --target web --out-dir /wasm-out src/frontend

# ---------------------------------------------------------------------------
# Stage 2: Native binaries (backend + admin)
# ---------------------------------------------------------------------------
FROM rust:slim AS native-builder

RUN apt-get update && apt-get install -y --no-install-recommends \
    pkg-config libssl-dev \
  && rm -rf /var/lib/apt/lists/*

WORKDIR /build

COPY Cargo.toml Cargo.lock ./
COPY src/core src/core
COPY src/backend src/backend
COPY tools/admin tools/admin
# Stub the frontend (wasm32-only, not needed here).
RUN mkdir -p src/frontend/src && \
    printf '[package]\nname="chorgly-frontend"\nversion="0.1.0"\nedition="2021"\n[lib]\ncrate-type=["cdylib"]\n' > src/frontend/Cargo.toml && \
    printf '' > src/frontend/src/lib.rs

RUN cargo build --release --package chorgly-backend --package chorgly-admin

# ---------------------------------------------------------------------------
# Stage 3: Runtime
# ---------------------------------------------------------------------------
FROM debian:bookworm-slim AS runtime

RUN apt-get update && apt-get install -y --no-install-recommends \
    libssl3 ca-certificates git \
  && rm -rf /var/lib/apt/lists/*

# Copy binaries.
COPY --from=native-builder /build/target/release/chorgly-backend /usr/local/bin/
COPY --from=native-builder /build/target/release/chorgly-admin   /usr/local/bin/

# Copy pre-built static webapp.
COPY --from=wasm-builder /wasm-out /app/static/pkg
COPY docs/app.html docs/app.js docs/app.css docs/index.html docs/style.css /app/static/

# Data volume (git-backed CBOR store).
VOLUME ["/data"]

# Config volume (reserved; read-only in deployment).
VOLUME ["/config"]

ENV CHORGLY_PORT=8080
ENV CHORGLY_DATA=/data
ENV CHORGLY_STATIC_DIR=/app/static

EXPOSE 8080

ENTRYPOINT ["/usr/local/bin/chorgly-backend"]
