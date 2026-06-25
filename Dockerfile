FROM lukemathwalker/cargo-chef:latest-rust-1 AS chef
WORKDIR /app

FROM chef AS planner
COPY . .
# Compute a lock-like file for our project
RUN cargo chef prepare --recipe-path recipe.json

FROM chef AS builder
COPY --from=planner /app/recipe.json recipe.json
# Build project dependencies, not our application!
RUN cargo chef cook --release --recipe-path recipe.json
COPY . .
RUN cargo build --release --bin myapp-mcp

# Distroless CC (glibc support) on Debian 13, running as a secure non-root user
FROM gcr.io/distroless/cc-debian13:nonroot AS runtime
WORKDIR /app

# Copy the binary from the builder, ensuring the nonroot user owns it
COPY --chown=nonroot:nonroot --from=builder /app/target/release/myapp-mcp /app/myapp-mcp

# Bind on all interfaces inside the container so published ports are reachable
# (the binary otherwise defaults to 127.0.0.1:8080).
ENV MYAPP_MCP_HOST=0.0.0.0 \
    MYAPP_MCP_PORT=8080
EXPOSE 8080

ENTRYPOINT ["/app/myapp-mcp"]
# Default to the HTTP transport for container deployments (override as needed;
# the binary's own default transport is stdio).
CMD ["--transport", "http"]
