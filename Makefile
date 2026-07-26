# ratarmount-rs development helpers (Phase 11)

.PHONY: build release test suite install clean help check package-notes appimage packages

CARGO ?= cargo
PREFIX ?= $(HOME)/.local
BINDIR ?= $(PREFIX)/bin

help:
	@echo "Targets:"
	@echo "  make build         - debug build"
	@echo "  make release       - release build"
	@echo "  make test          - cargo test --workspace"
	@echo "  make check         - fmt + clippy -D warnings + test"
	@echo "  make suite         - full phase harness suite (needs RATARMOUNT_PY_ROOT)"
	@echo "  make install       - install release binary to $(BINDIR)"
	@echo "  make appimage      - stage AppDir / AppImage (packaging/build-appimage.sh)"
	@echo "  make packages      - .deb/.rpm + tarball (packaging/build-native-packages.sh)"
	@echo "  make package-notes - print packaging docs path"
	@echo "  make clean         - cargo clean"

build:
	$(CARGO) build

release:
	$(CARGO) build --release

test:
	$(CARGO) test --workspace

check:
	$(CARGO) fmt --all -- --check
	$(CARGO) clippy --workspace --all-targets -- -D warnings
	$(CARGO) test --workspace

suite: release
	RATARMOUNT_CMD=$(CURDIR)/target/release/ratarmount ./test-harness/run-all-phases.sh

install: release
	install -d $(BINDIR)
	install -m 755 target/release/ratarmount $(BINDIR)/ratarmount
	@echo "Installed $(BINDIR)/ratarmount"

package-notes:
	@echo "See docs/packaging.md for AppImage / distro notes"
	@echo "Desktop entry: packaging/ratarmount.desktop"
	@echo "Build script:  packaging/build-appimage.sh"

appimage: release
	./packaging/build-appimage.sh

packages: release
	./packaging/build-native-packages.sh

clean:
	$(CARGO) clean
