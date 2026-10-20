# syntax=docker/dockerfile:1
# Quisora container image: a static binary (web assets embedded) on a distroless base, running as a non-root user.
#
#   docker build -t quisora .
#   docker run -p 8443:8443 -v quisora-data:/data -e QUISORA_PUBLIC_URL=https://localhost:8443 \
#     -e QUISORA_BOOTSTRAP_ADMIN=admin@example.com quisora
#
# Every setting is an QUISORA_* environment variable, a flag after "serve", or /etc/quisora/quisora.toml (mount it).

ARG NODE_VERSION=24.15.0
ARG GO_VERSION=1.27.2

FROM node:${NODE_VERSION}-alpine AS web
WORKDIR /src/web
COPY web/package.json web/package-lock.json ./
RUN npm ci --no-audit --no-fund --ignore-scripts
COPY web/ ./
RUN npm run build

FROM golang:${GO_VERSION}-alpine AS build
ARG VERSION=dev
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
COPY --from=web /src/web/dist ./web/dist
RUN CGO_ENABLED=0 go build -trimpath \
      -ldflags "-s -w -X github.com/paularlott/quisora/internal/build.Version=${VERSION}" \
      -o /out/quisora . \
 && mkdir -p /out/data

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/quisora /usr/local/bin/quisora
COPY --from=build --chown=nonroot:nonroot /out/data /data
WORKDIR /data
ENV QUISORA_LISTEN=0.0.0.0:8443 \
    QUISORA_DATA_DIR=/data
VOLUME ["/data"]
# 8443: HTTPS (the only listener). 7946: cluster gossip, when QUISORA_CLUSTER_BIND is set.
EXPOSE 8443 7946/tcp 7946/udp
USER nonroot:nonroot
# Liveness: a cluster node that is catching up or cut off from the majority is alive but not ready, and must not be
# restarted for it. Point load balancers at /readyz ("quisora healthcheck --ready").
HEALTHCHECK --interval=15s --timeout=6s --start-period=20s --retries=3 CMD ["quisora", "healthcheck"]
ENTRYPOINT ["quisora"]
CMD ["serve"]
