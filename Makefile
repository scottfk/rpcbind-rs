# Makefile - convenience targets for rpcbind-rs
#
# 20261121 - Created by Claude (claude.ai, Anthropic) - scottfk

REFERENCE ?= ../rpcbind

.PHONY: all reference check clippy fmt clean

all:
	cargo build --release

reference:
	tools/build-reference.sh $(REFERENCE)

check:
	@test -x $(REFERENCE)/rpcbind || tools/build-reference.sh $(REFERENCE)
	RPCBIND_REFERENCE=$(abspath $(REFERENCE)) cargo test --release

clippy:
	cargo clippy --all-targets -- -D warnings

fmt:
	cargo fmt

clean:
	cargo clean
