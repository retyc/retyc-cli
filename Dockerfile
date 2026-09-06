FROM golang:1.25.9 AS builder

ARG VERSION=dev

WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 go build \
    -tags prod \
    -ldflags "-s -w -X github.com/retyc/retyc-cli/cmd.Version=${VERSION}" \
    -o /retyc .

RUN useradd --no-log-init -u 1000 -U -m retyc && \
    mkdir -p /home/retyc/.config/retyc

# ---

FROM scratch

COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=builder /etc/passwd /etc/passwd
COPY --from=builder /etc/group /etc/group
COPY --from=builder --chown=1000:1000 /home/retyc /home/retyc
COPY --from=builder /retyc /retyc

# OCI image annotations. `source` links the GHCR package to this repository
# (it shows up under the repo's Packages and inherits its access settings).
# Dynamic ones (revision, created) are injected by the workflow.
ARG VERSION=dev
LABEL org.opencontainers.image.title="retyc-cli" \
      org.opencontainers.image.description="Official command-line interface and MCP server for Retyc: send transfers and manage datarooms from your terminal." \
      org.opencontainers.image.source="https://github.com/retyc/retyc-cli" \
      org.opencontainers.image.url="https://retyc.com" \
      org.opencontainers.image.documentation="https://github.com/retyc/retyc-cli#readme" \
      org.opencontainers.image.vendor="Retyc" \
      org.opencontainers.image.licenses="MIT" \
      org.opencontainers.image.version="${VERSION}"

USER 1000:1000
ENV HOME=/home/retyc \
    XDG_CONFIG_HOME=/home/retyc/.config \
    XDG_CACHE_HOME=/home/retyc/.cache \
    XDG_DATA_HOME=/home/retyc/.local/share

VOLUME ["/home/retyc/.config/retyc"]

ENTRYPOINT ["/retyc"]
