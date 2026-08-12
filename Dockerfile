# syntax=docker/dockerfile:1

FROM golang:1.22.2-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY cmd ./cmd
COPY internal ./internal
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
    go build -trimpath -ldflags='-s -w' -o /out/wsn-server ./cmd/wsn-server

FROM scratch
COPY --from=build /out/wsn-server /wsn-server
USER 65532:65532
ENTRYPOINT ["/wsn-server"]
CMD ["-config", "/etc/wsn/server.json"]
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD ["/wsn-server", "healthcheck"]
