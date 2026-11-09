FROM rust:1.98.0-bookworm@sha256:e70e2eec3d495fd5c8e0be74adda86507dfac7f51a724fbf9813ff59b2b247c7

WORKDIR /workspace

RUN rustup component add clippy

COPY Cargo.toml Cargo.lock ./
COPY crates ./crates
COPY fuzz ./fuzz
COPY .github/docker/run-quality.sh /usr/local/bin/radiata-container-quality

ENV RUSTFLAGS="-Dwarnings"
ENV RUSTDOCFLAGS="-Dwarnings"

ENTRYPOINT ["/usr/local/bin/radiata-container-quality"]
