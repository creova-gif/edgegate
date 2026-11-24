FROM rust:1.85-bookworm AS builder
WORKDIR /app
COPY Cargo.toml Cargo.lock* ./
COPY src ./src
RUN cargo build --release --bin edgegate

FROM gcr.io/distroless/cc-debian12:nonroot
COPY --from=builder /app/target/release/edgegate /usr/local/bin/edgegate
COPY edgegate.demo.toml /etc/edgegate/edgegate.toml
EXPOSE 8080
ENTRYPOINT ["/usr/local/bin/edgegate"]
CMD ["start", "--config", "/etc/edgegate/edgegate.toml"]
