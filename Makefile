SHELL := /bin/bash

.PHONY: fmt vet lint test build

fmt:
	go fmt ./...

vet:
	go vet ./...

lint:
	go run github.com/golangci/golangci-lint/v2/cmd/golangci-lint run ./...

test:
	go test ./...

build:
	go build ./cmd/fake-cloud-kms
