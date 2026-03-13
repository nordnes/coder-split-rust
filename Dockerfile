# ── Stage 1: Chef planner ─────────────────────────────────────────────
FROM rust:1.85-bookworm AS chef
RUN cargo install cargo-chef --locked
WORKDIR /app

# ── Stage 2: Prepare recipe (dependency fingerprint) ──────────────────
FROM chef AS planner
COPY . .
RUN cargo chef prepare --recipe-path recipe.json

# ── Stage 3: Build dependencies (cached layer) ───────────────────────
FROM chef AS builder
COPY --from=planner /app/recipe.json recipe.json
RUN cargo chef cook --release --recipe-path recipe.json

# Build the actual application
COPY . .
RUN cargo build --release --bin coderd

# ── Stage 4: Minimal runtime ─────────────────────────────────────────
FROM debian:bookworm-slim AS runtime

RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates \
        curl \
        libssl3 \
    && rm -rf /var/lib/apt/lists/*

# Create non-root user
RUN groupadd --gid 1000 coderd \
    && useradd --uid 1000 --gid coderd --shell /bin/false coderd

COPY --from=builder /app/target/release/coderd /usr/local/bin/coderd

USER coderd

EXPOSE 3000

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD curl -f http://localhost:3000/healthz || exit 1

ENTRYPOINT ["coderd"]
CMD ["server", "--listen-addr", "0.0.0.0:3000"]
