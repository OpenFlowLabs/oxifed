FROM cgr.dev/chainguard/rust:latest-dev as build
ARG PACKAGE
USER root
RUN apk update && apk add --no-cache --update-cache pkgconf openssl openssl-dev
USER nonroot
WORKDIR /app
ADD . .
RUN cargo build --release -p ${PACKAGE}

FROM cgr.dev/chainguard/wolfi-base
ARG PACKAGE
USER root
RUN adduser -D nonroot
RUN apk update && apk add --no-cache --update-cache openssl libgcc
USER nonroot
COPY --from=build --chown=nonroot:nonroot /app/target/release/${PACKAGE} /usr/local/bin/${PACKAGE}
ENV PACKAGE=${PACKAGE}
ENTRYPOINT "/usr/local/bin/${PACKAGE}"