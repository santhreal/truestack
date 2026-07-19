# syntax=docker/dockerfile:1
# Truestack - Technology stack fingerprinting tool

FROM rust:1.85 AS builder

WORKDIR /build

COPY . .

RUN cargo build --release

# Runtime stage
FROM debian:bookworm-slim

# Install runtime dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    libssl3 \
    && rm -rf /var/lib/apt/lists/*

# Create non-root user
RUN groupadd -r nonroot && useradd -r -g nonroot nonroot

# Copy binary from builder
COPY --from=builder /build/target/release/truestack /usr/local/bin/truestack

# Set up permissions
RUN chmod +x /usr/local/bin/truestack

USER nonroot

# Health check
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
    CMD truestack --help > /dev/null || exit 1

ENTRYPOINT ["truestack"]
