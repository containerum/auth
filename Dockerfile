FROM golang:1.10-alpine as builder
RUN apk add --update make git
WORKDIR src/git.containerum.net/ch/auth
COPY . .
RUN VERSION=$(git describe --abbrev=0 --tags) make build-for-docker

FROM alpine:3.7

VOLUME ["/keys", "/storage"]

COPY --from=builder /tmp/auth /
ENV HTTP_LISTENADDR=0.0.0.0:1111 \
    GRPC_LISTENADDR=0.0.0.0:1112 \
    LOG_MODE=text \
    LOG_LEVEL=4 \
    TOKENS=jwt \
    JWT_SIGNING_METHOD=HS256 \
    ISSUER=containerum.com \
    ACCESS_TOKEN_LIFETIME=15m \
    REFRESH_TOKEN_LIFETIME=48h \
    JWT_SIGNING_KEY_FILE=/keys/jwt.key \
    JWT_VALIDATION_KEY_FILE=/keys/jwt.key \
    STORAGE=buntdb \
    BUNT_STORAGE_FILE=/storage/storage.db \
    TRACER=zipkin \
    ZIPKIN_COLLECTOR=nop

EXPOSE 1111 1112

CMD ["/auth"]
