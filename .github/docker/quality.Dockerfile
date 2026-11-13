FROM rust:1.99.0-bookworm@sha256:114c7a4425406451c2866b6aafe69fe29b1b298832db1277d411ac73c82d04d6

WORKDIR /workspace

RUN rustup component add clippy

COPY Cargo.toml Cargo.lock ./
COPY crates ./crates
COPY fuzz ./fuzz
COPY .github/docker/run-quality.sh /usr/local/bin/radiata-container-quality

ENV RUSTFLAGS="-Dwarnings"
ENV RUSTDOCFLAGS="-Dwarnings"

ENTRYPOINT ["/usr/local/bin/radiata-container-quality"]
