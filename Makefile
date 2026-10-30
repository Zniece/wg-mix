PREFIX ?= /usr
DESTDIR ?=
BINDIR ?= $(PREFIX)/bin
export GO111MODULE := on

all: generate-version-and-build wgmix-ebpf

MAKEFLAGS += --no-print-directory

generate-version-and-build:
	@export GIT_CEILING_DIRECTORIES="$(realpath $(CURDIR)/..)" && \
	tag="$$(git describe --dirty 2>/dev/null)" && \
	ver="$$(printf 'package main\n\nconst Version = "%s"\n' "$$tag")" && \
	[ "$$(cat version.go 2>/dev/null)" != "$$ver" ] && \
	echo "$$ver" > version.go && \
	git update-index --assume-unchanged version.go || true
	@$(MAKE) wgmix

wgmix: $(wildcard *.go) $(wildcard */*.go)
	go build -v -o "$@"

wgmix-ebpf:
	@$(MAKE) -C ebpf BIN=wgmix-ebpf

install: wgmix wgmix-ebpf
	@install -v -d "$(DESTDIR)$(BINDIR)" && \
	install -v -m 0755 wgmix "$(DESTDIR)$(BINDIR)/wgmix" && \
	install -v -m 0755 ebpf/wgmix-ebpf "$(DESTDIR)$(BINDIR)/wgmix-ebpf"

test:
	go test ./...
	@$(MAKE) -C ebpf test

clean:
	rm -f wgmix wireguard-mix
	@$(MAKE) -C ebpf clean

.PHONY: all clean test install generate-version-and-build wgmix wgmix-ebpf
