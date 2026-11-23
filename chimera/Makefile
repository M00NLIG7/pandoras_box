RELEASE_TARGET := x86_64-unknown-linux-musl

.PHONY: all check test release-linux

all: check test release-linux

check:
	cargo fmt --all -- --check
	cargo clippy --locked --offline -p chimera --all-targets -- -D warnings

test:
	cargo test --locked --offline -p chimera

release-linux:
	cross build --locked --release -p chimera --bin chimera --target $(RELEASE_TARGET)
