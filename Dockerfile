# syntax=docker/dockerfile:1

FROM --platform=$BUILDPLATFORM golang:1.25-alpine AS build
# Populated automatically by buildx; the defaults keep a plain `docker build`
# producing the same linux/amd64 image it always did.
ARG TARGETOS=linux
ARG TARGETARCH=amd64
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY cmd ./cmd
COPY internal ./internal
RUN CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} \
    go build -trimpath -ldflags='-s -w' -o /out/wsn-server ./cmd/wsn-server

FROM scratch
COPY --from=build /out/wsn-server /wsn-server
USER 65532:65532
ENTRYPOINT ["/wsn-server"]
CMD ["-config", "/etc/wsn/server.json"]
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD ["/wsn-server", "healthcheck"]
