export PATH := $(HOME)/bin/go/bin:$(PATH)

BINARY  := vault-gateway
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
LDFLAGS := -ldflags "-s -w -X main.version=$(VERSION)"

.PHONY: build test cover lint run clean hooks

build:
	go build -trimpath $(LDFLAGS) -o $(BINARY) ./cmd/server

test:
	go test ./...

cover:
	go test -coverprofile=coverage.out ./...
	go tool cover -html=coverage.out

lint:
	golangci-lint run ./...

run:
	go run ./cmd/server

hooks:
	git config core.hooksPath .githooks

clean:
	rm -f $(BINARY) coverage.out
