FROM golang:1.24 AS builder

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

USER 1000:1000

VOLUME ["/home/retyc/.config/retyc"]

ENTRYPOINT ["/retyc"]
