# syntax=docker/dockerfile:1
# Quisora container image: a static binary (web assets embedded) on a distroless base, running as a non-root user.
#
#   docker build -t quisora .
#   docker build --build-arg GO_TAGS=onepassword -t quisora:1password .   # with 1Password service accounts
#   docker run -p 8443:8443 -v quisora-data:/data -e QUISORA_PUBLIC_URL=https://localhost:8443 \
#     -e QUISORA_BOOTSTRAP_ADMIN=admin@example.com quisora
#
# Every setting is an QUISORA_* environment variable, a flag after "serve", or /etc/quisora/quisora.toml (mount it).

# Base images are pinned by digest (the multi-platform index), so a build uses exactly the images that were reviewed
# even if a tag is moved. With a tag and a digest the digest decides: change a version and its digest together, e.g.
#   skopeo inspect --raw docker://docker.io/library/golang:1.27.3-alpine | shasum -a 256
ARG NODE_VERSION=24.15.0
ARG NODE_DIGEST=sha256:d1b3b4da11eefd5941e7f0b9cf17783fc99d9c6fc34884a665f40a06dbdfc94f
ARG GO_VERSION=1.27.3
ARG GO_DIGEST=sha256:b8c9b82affbbb82a020bbcf998dad2ba9516944ac7e883524642a481a9505e9c
ARG DISTROLESS_DIGEST=sha256:afa5c872c891853ca7fcf1f12c3edb23f7eeef36189728842dd51042ff57f7ab

FROM node:${NODE_VERSION}-alpine@${NODE_DIGEST} AS web
WORKDIR /src/web
COPY web/package.json web/package-lock.json ./
RUN npm ci --no-audit --no-fund --ignore-scripts
COPY web/ ./
RUN npm run build

FROM golang:${GO_VERSION}-alpine@${GO_DIGEST} AS build
ARG VERSION=dev
# "onepassword" links the 1Password SDK for service accounts (secrets.onepassword.service_account_token)
ARG GO_TAGS=
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
COPY --from=web /src/web/dist ./web/dist
RUN CGO_ENABLED=0 go build -trimpath -tags "${GO_TAGS}" \
      -ldflags "-s -w -X github.com/paularlott/quisora/internal/build.Version=${VERSION}" \
      -o /out/quisora . \
 && mkdir -p /out/data

FROM gcr.io/distroless/static-debian12:nonroot@${DISTROLESS_DIGEST}
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
