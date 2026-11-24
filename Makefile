MODULE   := github.com/retyc/retyc-cli
# The CLI (.) and the core module (core/), which go.mod replaces with ./core.
MODULES  := . core
BINARY   := retyc
VERSION  ?= $(shell git describe --tags --match 'v*' --always --dirty 2>/dev/null || echo "dev")
LDFLAGS  := -X $(MODULE)/cmd.Version=$(VERSION)

.PHONY: all build build-prod test test-coverage vet lint lint-fix clean install goreleaser goreleaser-full goreleaser-quick mcpb

## Default target: dev build (config in .retyc/ relative to CWD)
all: build

## Dev build — no prod tag, config dir is .retyc/ (CWD)
build:
	go build -ldflags "$(LDFLAGS)" -o $(BINARY) .

## Prod build — config dir is ~/.config/retyc/ (XDG)
build-prod:
	go build -tags prod -ldflags "$(LDFLAGS)" -o $(BINARY) .

## Run tests with race detector, in both modules
test:
	@for m in $(MODULES); do (cd $$m && go test -race ./...) || exit 1; done

## Run tests with coverage report and generate HTML report
test-coverage:
	go test -race -coverprofile=coverage.out ./...
	cd core && go test -race -coverprofile=../coverage-core.out ./...
	tail -n +2 coverage-core.out >>coverage.out && rm -f coverage-core.out
	go tool cover -func=coverage.out | tail -1
	go tool cover -html=coverage.out -o coverage.html
	@echo "Coverage report: coverage.html"

## Run go vet, in both modules
vet:
	@for m in $(MODULES); do (cd $$m && go vet ./...) || exit 1; done

## Run golangci-lint, in both modules
lint:
	@for m in $(MODULES); do (cd $$m && golangci-lint run ./...) || exit 1; done

## Run golangci-lint --fix, in both modules
lint-fix:
	@for m in $(MODULES); do (cd $$m && golangci-lint run ./... --fix) || exit 1; done

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
