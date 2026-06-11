MODULE   := github.com/retyc/retyc-cli
BINARY   := retyc
VERSION  ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
LDFLAGS  := -X $(MODULE)/cmd.Version=$(VERSION)

.PHONY: all build build-prod test test-coverage vet lint lint-fix clean install goreleaser mcpb

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

## Simple local release
goreleaser:
	goreleaser release --snapshot --clean

## Build the MCPB bundle (Claude Desktop extension) into dist/
## Requires goreleaser, jq, zip — no Node.js
mcpb: goreleaser
	scripts/build-mcpb.sh
