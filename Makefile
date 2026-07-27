#!/bin/make
# The Rust crate is the primary implementation; the Go tree is still present
# during the migration and is built by the `go-*` targets.
GOROOT:=$(shell PATH="/pkg/main/dev-lang.go.dev/bin:$$PATH" go env GOROOT)
GOPATH:=$(shell $(GOROOT)/bin/go env GOPATH)

.PHONY: all build test fmt lint doc go-all go-deps go-test

all: build

build:
	cargo build --all-features

test:
	cargo test --all-features

fmt:
	cargo fmt

lint:
	cargo clippy --all-targets --all-features

doc:
	cargo doc --no-deps --all-features

go-all:
	GOROOT="$(GOROOT)" $(GOPATH)/bin/goimports -w -l .
	$(GOROOT)/bin/go build -v

go-deps:
	$(GOROOT)/bin/go get -v -t .

go-test:
	$(GOROOT)/bin/go test -v ./...
