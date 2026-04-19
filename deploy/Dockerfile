# syntax=docker/dockerfile:1.7
#
# Build krone-groups-server as a static(ish) binary and copy into a distroless runtime.

ARG RUST_VERSION=1.95
FROM rust:${RUST_VERSION}-slim-bookworm AS builder

WORKDIR /app

# Pre-fetch deps via a dummy target for better layer caching.
COPY Cargo.toml Cargo.lock ./
RUN mkdir -p src && echo 'fn main(){}' > src/main.rs && \
    echo '' > src/lib.rs && \
    cargo build --release && \
    rm -rf src target/release/deps/krone_groups_server* target/release/krone-groups-server*

# Now copy the real sources and build for real.
COPY src ./src
COPY migrations ./migrations
COPY protocol ./protocol

RUN cargo build --release

# Runtime stage.
FROM gcr.io/distroless/cc-debian12 AS runtime

WORKDIR /app
COPY --from=builder /app/target/release/krone-groups-server /usr/local/bin/krone-groups-server
COPY --from=builder /app/migrations /app/migrations

ENV KRONE_BIND=0.0.0.0:8080 \
    KRONE_DATA_DIR=/data

VOLUME ["/data"]
EXPOSE 8080

USER nonroot:nonroot

ENTRYPOINT ["/usr/local/bin/krone-groups-server"]
