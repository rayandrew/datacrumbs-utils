# Generic Probe Attach POC

This POC demonstrates a kernel-5.14-friendly way to attach one kprobe and one uprobe at runtime through a single helper function.

It deliberately uses the stable single-probe libbpf helpers:

- `bpf_program__attach_kprobe_opts`
- `bpf_program__attach_uprobe_opts`

The BPF object uses generic section names:

- `SEC("kprobe")`
- `SEC("uprobe")`

The user-space loader decides the real targets at runtime and also populates a config map that tells the generic BPF handler which arguments to capture as raw bytes and how userspace should interpret them.

## What it does

- Attaches a kprobe to `openat` by default.
- Resolves the `open` symbol from the current libc to a file offset.
- Attaches a uprobe to that libc symbol for the current process.
- Populates a `arg_configs` map keyed by function id.
- Uses the generic BPF handler to look up the configured argument indexes and copy raw bytes into the event.
- Translates those raw bytes in userspace and prints them with per-function labels.
- Triggers both probes with a single `open()` call to `/dev/null`.
- Prints the events received through a ring buffer.

## Config map model

The loader defines a small config table and writes it into the `arg_configs` BPF map before attaching:

- `function_id`: stable id used by the generic handler
- `probe_kind`: kprobe or uprobe
- `function_name`: label printed in events
- `arg_count`: number of arguments to capture
- `arg_index[]`: which register-backed arguments to read
- `arg_num_bytes[]`: how many bytes the logical argument uses
- `arg_is_pointer[]`: whether the captured register value should be treated as a pointer
- `arg_label[][]`: userspace print labels for each configured argument
- `arg_c_type[][]`: userspace display type for translated output

The BPF programs stay generic and call a single helper:

- `trace_kernel()` calls `emit_event(ctx, 1)`
- `trace_user()` calls `emit_event(ctx, 2)`

`emit_event()` performs the map lookup and captures raw argument bytes only.
Userspace then formats those raw bytes according to `arg_num_bytes`, `arg_is_pointer`, and `arg_c_type`.
For pointer arguments, the BPF side copies bytes from kernel or user memory without interpreting them; userspace performs all type conversion and formatting.

## Build

```bash
cd tests/poc/probe-attach-generic
make
```

If `pkg-config` cannot find `libbpf`, provide `PREFIX` with the libbpf installation prefix:

```bash
make PREFIX=/path/to/libbpf/prefix
```

## Run

```bash
sudo ./probe_attach_generic
```

If your environment does not grant BPF loading privileges to the current shell, run it from a root shell or with the equivalent capabilities for BPF and perf events.

If the kernel does not expose `openat` as a direct kprobe symbol, the loader automatically falls back to common syscall aliases such as `__x64_sys_openat`.

You can override the default symbols:

```bash
sudo ./probe_attach_generic openat open
```

## Expected output

```text
resolved open in /lib64/libc.so.6 to file offset 0x...
attached kprobe to openat and uprobe to /lib64/libc.so.6:open
event=uprobe function=open id=2 pid=... tid=... comm=probe_attach_gen arg1=0x... arg2=0x...
event=kprobe function=openat id=1 pid=... tid=... comm=probe_attach_gen arg1=0x... arg2=0x...
```

With the current demo config, the translated output is intended to look like:

```text
event=uprobe function=open id=2 pid=... tid=... comm=probe_attach_gen pathname=(const char *)"/dev/null"@0x... flags=(int)0
event=kprobe function=openat id=1 pid=... tid=... comm=probe_attach_gen dfd=(int)4294967196 flags=(int)0
```

If a configured pointer argument can be read successfully, the event contains the raw pointed-to bytes plus the original address. Userspace converts those bytes into the requested display type. If the read fails, userspace falls back to printing the raw pointer value.

## Notes

- This example is intentionally small and does not use kprobe-multi or uprobe-multi, which keeps it suitable for older 5.14 kernels.
- The uprobe path is discovered with `dladdr`, and the symbol is converted from ELF virtual address to file offset before attaching.
- The kprobe path tries `openat` first and then common syscall symbol aliases if the direct symbol is unavailable.
- The BPF side does not perform type conversion. It only captures raw register values and, for pointer arguments, copies up to 32 raw bytes into the event.
- All interpretation of those bytes into scalar or pointer-typed output happens in userspace.
- The loader attempts to raise `RLIMIT_MEMLOCK` before loading the object, but you still need sufficient privileges to load and attach BPF programs.
- The intended invocation is with `sudo`, because loading and attaching BPF programs usually requires elevated privileges on 5.14 systems.