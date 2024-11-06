.PHONY: all clean build deps generate

# Compiler settings
GO=go
CLANG=clang
CFLAGS=-O2 -g -Wall -Werror

# Export for go generate
export BPF_CLANG := $(CLANG)
export BPF_CFLAGS := $(CFLAGS)

all: build

deps:
	$(GO) get github.com/cilium/ebpf/cmd/bpf2go@latest
	$(GO) get github.com/cilium/ebpf@latest
	$(GO) mod tidy

generate: deps
	$(GO) generate ./...

build: generate
	$(GO) build -o netmonitor ./cmd/main.go

clean:
	rm -f netmonitor
	rm -f pkg/ebpf/bpf_*.go
	rm -f pkg/ebpf/bpf_*.o

run: build
	sudo ./netmonitor
