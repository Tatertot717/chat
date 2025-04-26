FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y \
    openssl \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
