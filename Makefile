# Makefile - convenience targets for rpcbind-rs
#
# 20261121 - Created by Claude (claude.ai, Anthropic) - scottfk
# 20261123 - Build rpcinfo-rs before the tests, which run it - Claude - scottfk

REFERENCE ?= ../rpcbind

.PHONY: all reference check clippy fmt clean

all:
	cargo build --release

reference:
	tools/build-reference.sh $(REFERENCE)

check:
	@test -x $(REFERENCE)/rpcbind || tools/build-reference.sh $(REFERENCE)
	cargo build --release -p rpcinfo
	RPCBIND_REFERENCE=$(abspath $(REFERENCE)) cargo test --release

clippy:
	cargo clippy --all-targets -- -D warnings

fmt:
	cargo fmt

clean:
	cargo clean
