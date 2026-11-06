# Build context is the repository root:
#   docker build -f deploy/Dockerfile .
FROM rust:1.83-bookworm AS build
WORKDIR /app
COPY . .
# Only the server is built. The desktop app is a workspace member, so its
# manifest must be present for resolution, but -p keeps it from being compiled.
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/app/target \
    cargo build --release --locked -p credvault-server \
    && cp /app/target/release/credvault-server /usr/local/bin/credvault-server

FROM debian:bookworm-slim
# A fixed uid so the data volume's ownership survives image rebuilds.
RUN useradd --system --uid 10001 --create-home credvault \
    && mkdir -p /data \
    && chown credvault:credvault /data \
    && chmod 700 /data
COPY --from=build /usr/local/bin/credvault-server /usr/local/bin/credvault-server
USER credvault
ENV CREDVAULT_DATA_DIR=/data
VOLUME ["/data"]
EXPOSE 8787
ENTRYPOINT ["/usr/local/bin/credvault-server"]
