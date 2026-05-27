TARGET := probe_attach_generic
BPF_SRC := $(TARGET).bpf.c
BPF_OBJ := $(TARGET).bpf.o
SKEL := $(TARGET).skel.h
USER_SRC := $(TARGET).c
VMLINUX_H := vmlinux.h

CC ?= gcc
CLANG ?= clang
BPFTOOL ?= bpftool
CFLAGS ?= -D_GNU_SOURCE -Wall -Wextra -O2 -g
ARCH := $(shell uname -m | sed 's/x86_64/x86/' | sed 's/aarch64/arm64/')
BPF_CFLAGS := -target bpf -D__TARGET_ARCH_$(ARCH) -Wall -Wextra -O2 -g

LIBBPF_CFLAGS ?= $(shell pkg-config --cflags libbpf 2>/dev/null)
LIBBPF_LIBS ?= $(shell pkg-config --libs libbpf 2>/dev/null)

ifeq ($(strip $(LIBBPF_LIBS)),)
LIBBPF_CFLAGS := -I$(PREFIX)/include
LIBBPF_LIBS := $(PREFIX)/lib64/libbpf.so -lelf -lz
endif

all: $(TARGET)

$(VMLINUX_H):
	$(BPFTOOL) btf dump file /sys/kernel/btf/vmlinux format c > $@

$(BPF_OBJ): $(BPF_SRC) $(VMLINUX_H) probe_attach_generic.h
	$(CLANG) $(BPF_CFLAGS) $(LIBBPF_CFLAGS) -I. -c $< -o $@

$(SKEL): $(BPF_OBJ)
	$(BPFTOOL) gen skeleton $< > $@

$(TARGET): $(USER_SRC) $(SKEL) probe_attach_generic.h
	$(CC) $(CFLAGS) $(LIBBPF_CFLAGS) -I. $< -o $@ $(LIBBPF_LIBS) -ldl

clean:
	rm -f $(TARGET) $(BPF_OBJ) $(SKEL) $(VMLINUX_H)

.PHONY: all clean
