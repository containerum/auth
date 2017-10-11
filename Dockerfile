FROM golang:1.9-alpine as builder
COPY . src/bitbucket.org/exonch/ch-auth
RUN apk add --no-cache git && \
    go get -v -t -u ./... && \
    go test -v -cover ./...
RUN go build -v -ldflags="-w -s" -o /bin/ch-auth

FROM alpine:latest
COPY --from=builder /bin/ch-auth /bin
# TODO: add env
CMD /bin/ch-auth