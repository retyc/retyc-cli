MODULE   := github.com/retyc/retyc-cli
BINARY   := retyc
VERSION  ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
LDFLAGS  := -X $(MODULE)/cmd.Version=$(VERSION)

.PHONY: all build build-prod test test-coverage vet lint lint-fix clean install goreleaser goreleaser-full goreleaser-quick mcpb npm npm-test

## Default target: dev build (config in .retyc/ relative to CWD)
all: build

## Dev build — no prod tag, config dir is .retyc/ (CWD)
build:
	go build -ldflags "$(LDFLAGS)" -o $(BINARY) .

## Prod build — config dir is ~/.config/retyc/ (XDG)
build-prod:
	go build -tags prod -ldflags "$(LDFLAGS)" -o $(BINARY) .

## Run tests with race detector
test:
	go test -race ./...

## Run tests with coverage report and generate HTML report
test-coverage:
	go test -race -coverprofile=coverage.out ./...
	go tool cover -func=coverage.out | tail -1
	go tool cover -html=coverage.out -o coverage.html
	@echo "Coverage report: coverage.html"

## Run go vet
vet:
	go vet ./...

## Run golangci-lint
lint:
	golangci-lint run ./...

## Run golangci-lint --fix
lint-fix:
	golangci-lint run ./... --fix

## Remove built binary
clean:
	rm -f $(BINARY)
	rm -fr ./dist

## Install prod binary to GOBIN (defaults to ~/go/bin)
install:
	go install -tags prod -ldflags "$(LDFLAGS)" .

## Simple local release (every target, signed as in CI)
goreleaser: goreleaser-full

goreleaser-full:
	goreleaser release --snapshot --clean

## Quick local release: linux/amd64 only, no signature (as the CI package job)
goreleaser-quick:
	@tmp=$$(mktemp) && trap 'rm -f "$$tmp"' EXIT && \
	yq '.builds[0].goos = ["linux"] | .builds[0].goarch = ["amd64"]' .goreleaser.yaml >"$$tmp" && \
	goreleaser release --snapshot --clean --skip=sign --config "$$tmp"

## Build the MCPB bundle (Claude Desktop extension) into dist/
## Requires goreleaser, jq, zip — no Node.js
mcpb: goreleaser-full
	scripts/build-mcpb.sh

## Build the npm packages (@retyc/mcp + platform packages) into dist/npm/
## Requires goreleaser, jq; Node.js only for the smoke test
npm: goreleaser-full
	scripts/build-npm.sh

## Smoke-test the npm launcher on this host (linux/amd64 build only)
npm-test: goreleaser-quick
	scripts/build-npm.sh --host-only
	scripts/test-npm.sh
