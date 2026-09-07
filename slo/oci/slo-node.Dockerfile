# The release slo-node image (SC-G10-P0-30): built from the external
# path dependency at one exact source checkout and Cargo.lock digest.
# The build context is the repository root.
FROM rust:1.98-bookworm AS build
WORKDIR /build
COPY Cargo.toml Cargo.lock ./
COPY src ./src
COPY test-support ./test-support
COPY slo/Cargo.toml slo/Cargo.lock ./slo/
COPY slo/src ./slo/src
RUN cargo build --locked --release --manifest-path slo/Cargo.toml -p radiata-slo --bin slo-node

FROM debian:bookworm-slim
COPY --from=build /build/slo/target/release/slo-node /usr/local/bin/slo-node
ENV RADIATA_SLO_DATA=/data
VOLUME ["/data"]
ENTRYPOINT ["/usr/local/bin/slo-node"]
