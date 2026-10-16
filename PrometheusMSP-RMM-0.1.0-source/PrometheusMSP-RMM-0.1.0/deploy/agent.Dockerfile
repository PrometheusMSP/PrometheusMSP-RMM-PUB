# Build artifact image; endpoint agents should normally use the native service installers.
FROM golang:1.23-bookworm AS build
WORKDIR /src
COPY go.mod go.sum* ./
RUN --mount=type=cache,target=/go/pkg/mod go mod download
COPY . .
RUN --mount=type=cache,target=/go/pkg/mod --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags='-s -w' -o /out/prometheus-rmm-agent ./agent/cmd/prometheus-agent

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/prometheus-rmm-agent /usr/local/bin/prometheus-rmm-agent
USER nonroot:nonroot
ENTRYPOINT ["/usr/local/bin/prometheus-rmm-agent"]
