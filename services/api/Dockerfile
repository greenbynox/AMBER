FROM rust:1.77 as builder
WORKDIR /app
COPY Cargo.toml Cargo.lock ./
COPY crates ./crates
COPY services ./services
RUN cargo build --release -p ember-api

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y ca-certificates curl && rm -rf /var/lib/apt/lists/*
COPY --from=builder /app/target/release/ember-api /usr/local/bin/ember-api
EXPOSE 3002
CMD ["ember-api"]
