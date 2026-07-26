# ratarmount-rs development helpers (Phase 11)

.PHONY: build release test suite install clean help

CARGO ?= cargo
PREFIX ?= $(HOME)/.local
BINDIR ?= $(PREFIX)/bin

help:
	@echo "Targets:"
	@echo "  make build     - debug build"
	@echo "  make release   - release build"
	@echo "  make test      - cargo test --workspace"
	@echo "  make suite     - full phase harness suite (needs RATARMOUNT_PY_ROOT)"
	@echo "  make install   - install release binary to $(BINDIR)"
	@echo "  make clean     - cargo clean"

build:
	$(CARGO) build

release:
	$(CARGO) build --release

test:
	$(CARGO) test --workspace

suite: release
	RATARMOUNT_CMD=$(CURDIR)/target/release/ratarmount ./test-harness/run-all-phases.sh

install: release
	install -d $(BINDIR)
	install -m 755 target/release/ratarmount $(BINDIR)/ratarmount
	@echo "Installed $(BINDIR)/ratarmount"

clean:
	$(CARGO) clean
