FROM golang:1.9-alpine as builder
WORKDIR src/bitbucket.org/exonch/ch-auth
COPY . .
RUN CGO_ENABLED=0 go build -v -ldflags="-w -s -extldflags '-static'" -o /bin/ch-auth

FROM alpine:latest as alpine
RUN apk --no-cache add tzdata zip ca-certificates
WORKDIR /usr/share/zoneinfo
# -0 means no compression.  Needed because go's
# tz loader doesn't handle compressed data.
RUN zip -r -0 /zoneinfo.zip .

FROM scratch
# app
COPY --from=builder /bin/ch-auth /
# timezone data
ENV ZONEINFO /zoneinfo.zip
COPY --from=alpine /zoneinfo.zip /
# tls certificates
COPY --from=alpine /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
# TODO: add env
ENTRYPOINT ["/ch-auth"]