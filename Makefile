# Inkog CLI Makefile
# Build commands for the Inkog CLI (inkog-io/inkog)

# Version injection - can be overridden via make VERSION=x.y.z
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
BUILD_TIME := $(shell date -u '+%Y-%m-%dT%H:%M:%SZ')
GIT_COMMIT := $(shell git rev-parse --short HEAD 2>/dev/null || echo "unknown")

# Build flags
LDFLAGS := -X main.AppVersion=$(VERSION) -X main.BuildTime=$(BUILD_TIME) -X main.GitCommit=$(GIT_COMMIT)
LDFLAGS_PROD := $(LDFLAGS) -s -w

# Binary name
BINARY := inkog

.PHONY: all build build-prod test lint clean install help

all: build

## Build commands

build: ## Build the CLI binary
	CGO_ENABLED=0 go build -ldflags "$(LDFLAGS)" -o $(BINARY) ./cmd/cli

build-prod: ## Build production binary (stripped)
	CGO_ENABLED=0 go build -ldflags "$(LDFLAGS_PROD)" -o $(BINARY) ./cmd/cli

build-all: ## Build for all platforms
	GOOS=darwin GOARCH=amd64 CGO_ENABLED=0 go build -ldflags "$(LDFLAGS_PROD)" -o $(BINARY)-darwin-amd64 ./cmd/cli
	GOOS=darwin GOARCH=arm64 CGO_ENABLED=0 go build -ldflags "$(LDFLAGS_PROD)" -o $(BINARY)-darwin-arm64 ./cmd/cli
	GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -ldflags "$(LDFLAGS_PROD)" -o $(BINARY)-linux-amd64 ./cmd/cli
	GOOS=linux GOARCH=arm64 CGO_ENABLED=0 go build -ldflags "$(LDFLAGS_PROD)" -o $(BINARY)-linux-arm64 ./cmd/cli
	GOOS=windows GOARCH=amd64 CGO_ENABLED=0 go build -ldflags "$(LDFLAGS_PROD)" -o $(BINARY)-windows-amd64.exe ./cmd/cli

## Development

test: ## Run tests
	go test -v ./...

lint: ## Run linter
	go vet ./...
	@if command -v golangci-lint >/dev/null 2>&1; then golangci-lint run; fi

fmt: ## Format code
	go fmt ./...

## Installation

install: build ## Install to $GOPATH/bin
	cp $(BINARY) $(GOPATH)/bin/$(BINARY)

## Cleanup

clean: ## Remove build artifacts
	rm -f $(BINARY) $(BINARY)-*

## Docker

docker-build: ## Build Docker image
	docker build -t inkog:$(VERSION) .

## Help

help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-20s\033[0m %s\n", $$1, $$2}'
