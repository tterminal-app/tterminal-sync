FROM rust:1-alpine AS build
RUN apk add --no-cache musl-dev
WORKDIR /src
COPY Cargo.toml Cargo.lock ./
COPY server server
COPY vault vault
RUN cargo build --release --locked -p tterm-server

FROM alpine:3
RUN adduser -D -H -u 10001 tterm && mkdir /data && chown tterm:tterm /data
COPY --from=build /src/target/release/tterm-server /usr/local/bin/tterm-server
USER tterm
ENV TTERM_LISTEN=0.0.0.0:8722 TTERM_DATA=/data
VOLUME /data
EXPOSE 8722
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s \
    CMD wget -qO- http://127.0.0.1:8722/v1/health >/dev/null || exit 1
ENTRYPOINT ["tterm-server"]
