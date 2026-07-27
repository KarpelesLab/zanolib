#!/bin/make

.PHONY: all build test fmt lint doc

all: build

build:
	cargo build --all-features

test:
	cargo test --all-features
	cargo test --no-default-features

fmt:
	cargo fmt

lint:
	cargo clippy --all-targets --all-features -- -D warnings
	cargo fmt --check

doc:
	cargo doc --no-deps --all-features
