CARGO ?= cargo
GUEST_TARGET ?= x86_64-unknown-linux-musl
PREFIX ?= /usr/local
BINDIR := $(PREFIX)/bin

.PHONY: all build-guest build test test-offline install doctor bench initramfs clean

all: build-guest build

build-guest:
	$(CARGO) build --release --target $(GUEST_TARGET) -p sbx-guest-agent
	@ls -lh target/$(GUEST_TARGET)/release/sbx-guest-agent

build: build-guest
	$(CARGO) build --release --workspace

test: build-guest
	$(CARGO) test --workspace

test-offline: build-guest
	$(CARGO) test --offline --workspace

install: all
	install -d $(DESTDIR)$(BINDIR)
	install -m 0755 target/$(GUEST_TARGET)/release/sbx-guest-agent $(DESTDIR)$(BINDIR)/sbx-guest-agent
	install -m 0755 target/release/sbx $(DESTDIR)$(BINDIR)/sbx
	install -m 0755 target/release/sbx-daemon $(DESTDIR)$(BINDIR)/sbx-daemon
	install -m 0755 target/release/sbx-mcp $(DESTDIR)$(BINDIR)/sbx-mcp
	install -m 0755 target/release/containerd-shim-sbx-v2 $(DESTDIR)$(BINDIR)/containerd-shim-sbx-v2

doctor: build
	./target/release/sbx doctor

bench: build
	./target/release/sbx bench --image alpine --cold-trials 5 --iterations 50

initramfs: build-guest
	./deploy/kernel/build-kernel-initramfs.sh

clean:
	$(CARGO) clean
