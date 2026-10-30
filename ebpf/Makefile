BPF_CLANG  ?= clang
BPF_CFLAGS ?= -O2 -Wall
GO         ?= go
BIN        ?= wgmix-ebpf
CMD        ?= wg-mix-ebpf

BPF_SRC := bpf/typeobfs.bpf.c
BPF_HDR := bpf/typeobfs.h

.PHONY: all bpf build test fmt vet clean

all: bpf build

# 小端、大端各一份，供不同 GOARCH 选择。
bpf: bpf/typeobfs_bpfel.o bpf/typeobfs_bpfeb.o

bpf/typeobfs_bpfel.o: $(BPF_SRC) $(BPF_HDR)
	$(BPF_CLANG) $(BPF_CFLAGS) -target bpfel -I bpf -c $< -o $@

bpf/typeobfs_bpfeb.o: $(BPF_SRC) $(BPF_HDR)
	$(BPF_CLANG) $(BPF_CFLAGS) -target bpfeb -I bpf -c $< -o $@

build:
	CGO_ENABLED=0 GOOS=linux $(GO) build -trimpath -ldflags '-s -w' -o $(BIN) ./cmd/$(CMD)

test:
	$(GO) test ./...

fmt:
	$(GO) fmt ./...

vet:
	GOOS=linux $(GO) vet ./...

clean:
	rm -f bpf/typeobfs_bpfel.o bpf/typeobfs_bpfeb.o $(BIN)
