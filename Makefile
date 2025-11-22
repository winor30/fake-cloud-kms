SHELL := /bin/bash
PKGS := $(shell go list ./... | grep -v '^github.com/winor30/fake-cloud-kms/clients')
coverprofile ?= coverage.out

.PHONY: fmt vet lint test build coverage

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

coverage:
	go test -covermode=atomic -coverprofile=$(coverprofile) $(PKGS)
	go tool cover -func=$(coverprofile)
