MODULE   := github.com/retyc/retyc-cli
BINARY   := retyc
VERSION  ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
LDFLAGS  := -X $(MODULE)/cmd.Version=$(VERSION)

.PHONY: all build build-prod test vet lint clean install

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

## Run go vet
vet:
	go vet ./...

## Remove built binary
clean:
	rm -f $(BINARY)

## Install prod binary to GOBIN (defaults to ~/go/bin)
install:
	go install -tags prod -ldflags "$(LDFLAGS)" .
