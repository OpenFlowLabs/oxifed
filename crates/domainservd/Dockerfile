FROM rust:slim-bookworm as build

RUN apt update && apt install -y pkgconf openssl libssl-dev

ADD . .

RUN cargo build --release -p domainservd

FROM debian:bookworm-slim

COPY --from=build target/release/domainservd /usr/bin/domainservd

ENTRYPOINT ["domainservd"]
