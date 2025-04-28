FROM debian:bookworm-slim AS builder
RUN apt-get update && apt-get install -y --no-install-recommends \
    openssl \
    libssl-dev \
    libncurses-dev \
    ncurses-bin \
    build-essential \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY . .
RUN make release


FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends \
    openssl \
    ncurses-bin \
    libncurses-dev \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY --from=builder /app/build/release ./build/release
COPY --from=builder /app/certs ./certs
CMD [ "./build/release/server" ]