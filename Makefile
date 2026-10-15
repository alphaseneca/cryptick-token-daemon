SHELL := /bin/bash

# Auto-detect cargo binary
CARGO ?= $(shell command -v cargo 2>/dev/null || \
	for p in $(HOME)/.rustup/toolchains/stable-aarch64-apple-darwin/bin $(HOME)/.cargo/bin $(HOME)/.rustup/toolchains/stable-x86_64-apple-darwin/bin; do \
		if [ -x "$$p/cargo" ]; then echo "$$p/cargo"; break; fi; \
	done)
CARGO_DIR := $(dir $(CARGO))
export PATH := $(CARGO_DIR):$(PATH)

PREFIX ?= $(HOME)/.local

all: build

build:
	$(CARGO) build --workspace

release:
	$(CARGO) build --release -p daemon -p piv -p transport-ble -p sk-middleware -p webauthn-host

pkg:
	./packaging/macos/build_pkg.sh

deb:
	./packaging/linux/build_deb.sh

extension:
	./packaging/extension/build_extension.sh

dist: release extension
ifeq ($(shell uname -s),Darwin)
	./packaging/macos/build_pkg.sh
endif
	./packaging/linux/build_deb.sh

test:
	$(CARGO) test --workspace --all-features

clippy:
	$(CARGO) clippy --workspace --all-targets --all-features

check:
	$(CARGO) run -p daemon --bin cryptick-daemon -- check

status:
	$(CARGO) run -p daemon --bin cryptick-daemon -- service status

install:
	PREFIX="$(PREFIX)" ./tools/install.sh

uninstall:
	PREFIX="$(PREFIX)" ./tools/uninstall.sh

clean:
	cargo clean
	rm -rf target/packages target/pkg_root target/deb_root target/ext_staging

serve:
	@echo "Serving Cryptick Token showcase website on http://localhost:8000..."
	python3 -m http.server 8000 --directory site

