#include "probe_attach_generic.h"

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#include "vmlinux.h"

struct {
  __uint(type, BPF_MAP_TYPE_RINGBUF);
  __uint(max_entries, 1 << 20);
} events SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 16);
  __type(key, unsigned int);
  __type(value, struct arg_capture_config);
} arg_configs SEC(".maps");

static __always_inline unsigned long long read_cached_arg(
    unsigned long long arg1, unsigned long long arg2, unsigned long long arg3,
    unsigned long long arg4, unsigned long long arg5, unsigned int index) {
  switch (index) {
    case 0:
      return arg1;
    case 1:
      return arg2;
    case 2:
      return arg3;
    case 3:
      return arg4;
    case 4:
      return arg5;
    default:
      return 0;
  }
}

static __always_inline void capture_arg_bytes(struct probe_event* event,
                                              const struct arg_capture_config* config,
                                              unsigned int slot, unsigned long long raw_value) {
  unsigned long long scalar_value;
  unsigned int num_bytes;
  long err;

  event->args[slot] = raw_value;
  event->arg_data_status[slot] = 0;
  event->arg_data_len[slot] = 0;
  __builtin_memset(event->arg_data[slot], 0, sizeof(event->arg_data[slot]));

  num_bytes = config->arg_num_bytes[slot];
  if (num_bytes == 0) {
    return;
  }
  if (num_bytes > MAX_CAPTURE_BYTES) {
    num_bytes = MAX_CAPTURE_BYTES;
  }

  event->arg_data_len[slot] = num_bytes;
  if (config->arg_is_pointer[slot] && raw_value != 0) {
    if (config->probe_kind == PROBE_KIND_UPROBE) {
      err = bpf_probe_read_user(event->arg_data[slot], num_bytes, (const void*)raw_value);
    } else {
      err = bpf_probe_read_kernel(event->arg_data[slot], num_bytes, (const void*)raw_value);
    }
    event->arg_data_status[slot] = err == 0 ? 2 : 3;
    return;
  }

  scalar_value = raw_value;
  if (num_bytes > 0) event->arg_data[slot][0] = (unsigned char)(scalar_value & 0xff);
  if (num_bytes > 1) event->arg_data[slot][1] = (unsigned char)((scalar_value >> 8) & 0xff);
  if (num_bytes > 2) event->arg_data[slot][2] = (unsigned char)((scalar_value >> 16) & 0xff);
  if (num_bytes > 3) event->arg_data[slot][3] = (unsigned char)((scalar_value >> 24) & 0xff);
  if (num_bytes > 4) event->arg_data[slot][4] = (unsigned char)((scalar_value >> 32) & 0xff);
  if (num_bytes > 5) event->arg_data[slot][5] = (unsigned char)((scalar_value >> 40) & 0xff);
  if (num_bytes > 6) event->arg_data[slot][6] = (unsigned char)((scalar_value >> 48) & 0xff);
  if (num_bytes > 7) event->arg_data[slot][7] = (unsigned char)((scalar_value >> 56) & 0xff);
  event->arg_data_status[slot] = 1;
}

static __always_inline int emit_event(struct pt_regs* ctx, unsigned int function_id) {
  const struct arg_capture_config* config;
  struct probe_event* event;
  unsigned long long arg1;
  unsigned long long arg2;
  unsigned long long arg3;
  unsigned long long arg4;
  unsigned long long arg5;
  unsigned long long pid_tgid;
  unsigned int index;

  config = (const struct arg_capture_config*)bpf_map_lookup_elem(&arg_configs, &function_id);
  if (!config) {
    return 0;
  }

  event = (struct probe_event*)bpf_ringbuf_reserve(&events, sizeof(*event), 0);
  if (!event) {
    return 0;
  }

  arg1 = PT_REGS_PARM1(ctx);
  arg2 = PT_REGS_PARM2(ctx);
  arg3 = PT_REGS_PARM3(ctx);
  arg4 = PT_REGS_PARM4(ctx);
  arg5 = PT_REGS_PARM5(ctx);

  pid_tgid = bpf_get_current_pid_tgid();
  event->pid = pid_tgid >> 32;
  event->tid = (unsigned int)pid_tgid;
  event->probe_kind = config->probe_kind;
  event->function_id = config->function_id;
  event->arg_count = config->arg_count;
  bpf_get_current_comm(&event->comm, sizeof(event->comm));

  __builtin_memcpy(event->function_name, config->function_name, sizeof(event->function_name));
  for (index = 0; index < MAX_CAPTURE_ARGS; ++index) {
    event->args[index] = 0;
    event->arg_data_len[index] = 0;
    event->arg_data_status[index] = 0;
    __builtin_memset(event->arg_data[index], 0, sizeof(event->arg_data[index]));
  }
  for (index = 0; index < config->arg_count && index < MAX_CAPTURE_ARGS; ++index) {
    capture_arg_bytes(event, config, index,
                      read_cached_arg(arg1, arg2, arg3, arg4, arg5, config->arg_index[index]));
  }

  bpf_ringbuf_submit(event, 0);
  return 0;
}

SEC("kprobe")
int trace_kernel(struct pt_regs* ctx) {
  return emit_event(ctx, 1);
}

SEC("uprobe")
int trace_user(struct pt_regs* ctx) {
  return emit_event(ctx, 2);
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
