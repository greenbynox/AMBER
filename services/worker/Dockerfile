FROM rust:1.77 as builder
WORKDIR /app
COPY Cargo.toml Cargo.lock ./
COPY crates ./crates
COPY services ./services
RUN cargo build --release -p ember-worker

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y ca-certificates && rm -rf /var/lib/apt/lists/*
COPY --from=builder /app/target/release/ember-worker /usr/local/bin/ember-worker
CMD ["ember-worker"]
