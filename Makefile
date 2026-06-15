PREFIX ?= /usr
DESTDIR ?=
BINDIR ?= $(PREFIX)/bin
export GO111MODULE := on

# ── ENQ FPGA AEAD hardware offload (cgo) ────────────────────────────────
# fpga_cipher.go imports the C library libenq_aead via cgo, so CGO must be
# enabled. By default we link the driver straight from its source tree (the
# parent directory of this wireguard-go checkout) and bake in an rpath, so a
# system `make install` of the .so is NOT required to build or run the test
# binary. Override ENQ_AEAD_DIR to point elsewhere.
export CGO_ENABLED := 1
ENQ_AEAD_DIR ?= $(realpath $(CURDIR)/..)
ENQ_AEAD_LIB := $(ENQ_AEAD_DIR)/libenq_aead.so

export CGO_CFLAGS += -I$(ENQ_AEAD_DIR)
export CGO_LDFLAGS += -L$(ENQ_AEAD_DIR) -Wl,-rpath,$(ENQ_AEAD_DIR) -Wl,-rpath,/usr/local/lib

all: generate-version-and-build

MAKEFLAGS += --no-print-directory

# Build the FPGA AEAD shared object that cgo links against.
$(ENQ_AEAD_LIB): $(ENQ_AEAD_DIR)/libenq_aead.c $(ENQ_AEAD_DIR)/libenq_aead.h
	@$(MAKE) -C "$(ENQ_AEAD_DIR)"

generate-version-and-build:
	@export GIT_CEILING_DIRECTORIES="$(realpath $(CURDIR)/..)" && \
	tag="$$(git describe --dirty 2>/dev/null)" && \
	ver="$$(printf 'package main\n\nconst Version = "%s"\n' "$$tag")" && \
	[ "$$(cat version.go 2>/dev/null)" != "$$ver" ] && \
	echo "$$ver" > version.go && \
	git update-index --assume-unchanged version.go || true
	@$(MAKE) wireguard-go

wireguard-go: $(ENQ_AEAD_LIB) $(wildcard *.go) $(wildcard */*.go)
	go build -v -o "$@"

install: wireguard-go
	@install -v -d "$(DESTDIR)$(BINDIR)" && install -v -m 0755 "wireguard-go" "$(DESTDIR)$(BINDIR)/wireguard-go"
	@$(MAKE) -C "$(ENQ_AEAD_DIR)" install

test:
	go test ./...

clean:
	rm -f wireguard-go
	@$(MAKE) -C "$(ENQ_AEAD_DIR)" clean 2>/dev/null || true

.PHONY: all clean test install generate-version-and-build
