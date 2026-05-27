#include "probe_attach_generic.h"

#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <dlfcn.h>
#include <elf.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "probe_attach_generic.skel.h"

enum probe_target_type {
  PROBE_TARGET_KPROBE,
  PROBE_TARGET_UPROBE,
};

struct probe_spec {
  enum probe_target_type type;
  unsigned int function_id;
  const char* program_name;
  const char* symbol_name;
  const char* display_name;
  const char* binary_path;
  bool retprobe;
  pid_t pid;
  struct arg_capture_config config;
};

struct app_context {
  const struct probe_spec* specs;
  size_t spec_count;
};

static int seen_events;

static int libbpf_print_fn(enum libbpf_print_level level, const char* format, va_list args) {
  if (level == LIBBPF_DEBUG) {
    return 0;
  }
  return vfprintf(stderr, format, args);
}

static const char* probe_kind_to_string(unsigned int probe_kind) {
  switch (probe_kind) {
    case PROBE_KIND_KPROBE:
      return "kprobe";
    case PROBE_KIND_UPROBE:
      return "uprobe";
    default:
      return "unknown";
  }
}

static const struct probe_spec* find_spec_by_id(const struct app_context* app,
                                                unsigned int function_id) {
  size_t index;

  for (index = 0; index < app->spec_count; ++index) {
    if (app->specs[index].function_id == function_id) {
      return &app->specs[index];
    }
  }

  return NULL;
}

static void print_hex_bytes(const unsigned char* bytes, unsigned int count) {
  unsigned int index;

  for (index = 0; index < count; ++index) {
    printf("%02x", bytes[index]);
  }
}

static bool is_char_pointer_type(const char* c_type) {
  if (!c_type) {
    return false;
  }
  return strstr(c_type, "char *") != NULL;
}

static void print_string_bytes(const char* label, const char* c_type, const unsigned char* bytes,
                               unsigned int num_bytes) {
  unsigned int index;

  if (c_type) {
    printf(" %s=(%s)\"", label, c_type);
  } else {
    printf(" %s=\"", label);
  }

  for (index = 0; index < num_bytes && bytes[index] != '\0'; ++index) {
    unsigned char value = bytes[index];
    if (value == '\\' || value == '"') {
      printf("\\%c", value);
    } else if (value >= 32 && value <= 126) {
      printf("%c", value);
    } else {
      printf("\\x%02x", value);
    }
  }
  printf("\"");
}

static void print_value_with_width(const char* label, const char* c_type,
                                   const unsigned char* bytes, unsigned int num_bytes) {
  if (c_type) {
    printf(" %s=(%s)", label, c_type);
  } else {
    printf(" %s=", label);
  }

  switch (num_bytes) {
    case 1:
      printf("%u", (unsigned int)bytes[0]);
      return;
    case 2:
      printf("%u", (unsigned int)*(const uint16_t*)bytes);
      return;
    case 4:
      printf("%u", *(const uint32_t*)bytes);
      return;
    case 8:
      printf("%llu", (unsigned long long)*(const uint64_t*)bytes);
      return;
    default:
      printf("0x");
      print_hex_bytes(bytes, num_bytes);
      return;
  }
}

static void print_translated_arg(const struct probe_event* event,
                                 const struct arg_capture_config* config, unsigned int slot,
                                 unsigned long long raw_value) {
  const char* label = config->arg_label[slot][0] != '\0' ? config->arg_label[slot] : "arg";
  const char* c_type = config->arg_c_type[slot][0] != '\0' ? config->arg_c_type[slot] : NULL;
  unsigned int num_bytes = config->arg_num_bytes[slot];
  unsigned int data_len = event->arg_data_len[slot];
  const unsigned char* bytes = event->arg_data[slot];

  if (config->arg_is_pointer[slot]) {
    if (event->arg_data_status[slot] == 2 && data_len > 0) {
      if (is_char_pointer_type(c_type)) {
        print_string_bytes(label, c_type, bytes, data_len);
      } else {
        print_value_with_width(label, c_type, bytes, data_len);
      }
      printf("@%p", (void*)(uintptr_t)raw_value);
      return;
    }

    if (c_type) {
      printf(" %s=(%s)%p", label, c_type, (void*)(unsigned long)raw_value);
    } else {
      printf(" %s=%p", label, (void*)(unsigned long)raw_value);
    }
    return;
  }

  if (event->arg_data_status[slot] == 1 && data_len > 0) {
    print_value_with_width(label, c_type, bytes, data_len);
    return;
  }

  {
    unsigned char scalar_bytes[sizeof(raw_value)] = {0};
    memcpy(scalar_bytes, &raw_value, sizeof(raw_value));
    print_value_with_width(label, c_type, scalar_bytes,
                           num_bytes > sizeof(raw_value) ? sizeof(raw_value) : num_bytes);
  }
}

static int handle_event(void* ctx, void* data, size_t data_sz) {
  const struct app_context* app = (const struct app_context*)ctx;
  const struct probe_event* event = (const struct probe_event*)data;
  const struct probe_spec* spec;
  unsigned int index;

  (void)ctx;
  (void)data_sz;

  ++seen_events;
  printf("event=%s function=%s id=%u pid=%u tid=%u comm=%s",
         probe_kind_to_string(event->probe_kind), event->function_name, event->function_id,
         event->pid, event->tid, event->comm);
  spec = find_spec_by_id(app, event->function_id);
  if (!spec) {
    for (index = 0; index < event->arg_count && index < MAX_CAPTURE_ARGS; ++index) {
      printf(" arg%u=0x%llx", index + 1, event->args[index]);
    }
    printf("\n");
    return 0;
  }

  for (index = 0; index < event->arg_count && index < MAX_CAPTURE_ARGS; ++index) {
    print_translated_arg(event, &spec->config, index, event->args[index]);
  }
  printf("\n");
  return 0;
}

static void init_capture_config(struct arg_capture_config* config, unsigned int function_id,
                                unsigned int probe_kind, const char* function_name,
                                unsigned int arg_count, const unsigned int* arg_index,
                                const unsigned int* arg_num_bytes,
                                const unsigned int* arg_is_pointer, const char* const* arg_label,
                                const char* const* arg_c_type) {
  unsigned int index;

  memset(config, 0, sizeof(*config));
  config->function_id = function_id;
  config->probe_kind = probe_kind;
  config->arg_count = arg_count;
  snprintf(config->function_name, sizeof(config->function_name), "%s", function_name);
  for (index = 0; index < arg_count && index < MAX_CAPTURE_ARGS; ++index) {
    config->arg_index[index] = arg_index[index];
    config->arg_num_bytes[index] = arg_num_bytes[index];
    config->arg_is_pointer[index] = arg_is_pointer[index];
    if (arg_label && arg_label[index]) {
      snprintf(config->arg_label[index], sizeof(config->arg_label[index]), "%s", arg_label[index]);
    }
    if (arg_c_type && arg_c_type[index]) {
      snprintf(config->arg_c_type[index], sizeof(config->arg_c_type[index]), "%s",
               arg_c_type[index]);
    }
  }
}

static int open_mapped_file(const char* path, void** data_out, size_t* size_out) {
  struct stat st;
  int fd;
  void* data;

  fd = open(path, O_RDONLY);
  if (fd < 0) {
    return -errno;
  }
  if (fstat(fd, &st) != 0) {
    int err = -errno;
    close(fd);
    return err;
  }
  data = mmap(NULL, st.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
  close(fd);
  if (data == MAP_FAILED) {
    return -errno;
  }

  *data_out = data;
  *size_out = st.st_size;
  return 0;
}

static long file_offset_from_vaddr(const Elf64_Ehdr* ehdr, Elf64_Addr value) {
  const Elf64_Phdr* phdrs;
  unsigned short i;

  phdrs = (const Elf64_Phdr*)((const char*)ehdr + ehdr->e_phoff);
  for (i = 0; i < ehdr->e_phnum; ++i) {
    const Elf64_Phdr* phdr = &phdrs[i];
    if (phdr->p_type != PT_LOAD) {
      continue;
    }
    if (value < phdr->p_vaddr || value >= phdr->p_vaddr + phdr->p_memsz) {
      continue;
    }
    return (long)(phdr->p_offset + (value - phdr->p_vaddr));
  }

  return -ENOENT;
}

static int resolve_symbol_offset(const char* binary_path, const char* symbol_name,
                                 unsigned long* offset_out) {
  const Elf64_Ehdr* ehdr;
  const Elf64_Shdr* shdrs;
  void* data = NULL;
  size_t size = 0;
  int err;
  unsigned short i;

  err = open_mapped_file(binary_path, &data, &size);
  if (err != 0) {
    return err;
  }

  ehdr = (const Elf64_Ehdr*)data;
  if (size < sizeof(*ehdr) || memcmp(ehdr->e_ident, ELFMAG, SELFMAG) != 0 ||
      ehdr->e_ident[EI_CLASS] != ELFCLASS64) {
    munmap(data, size);
    return -EINVAL;
  }

  shdrs = (const Elf64_Shdr*)((const char*)data + ehdr->e_shoff);
  for (i = 0; i < ehdr->e_shnum; ++i) {
    const Elf64_Shdr* shdr = &shdrs[i];
    const Elf64_Sym* syms;
    const char* strtab;
    size_t j;
    size_t num_syms;

    if (shdr->sh_type != SHT_SYMTAB && shdr->sh_type != SHT_DYNSYM) {
      continue;
    }

    syms = (const Elf64_Sym*)((const char*)data + shdr->sh_offset);
    strtab = (const char*)data + shdrs[shdr->sh_link].sh_offset;
    num_syms = shdr->sh_size / shdr->sh_entsize;
    for (j = 0; j < num_syms; ++j) {
      long file_offset;
      const Elf64_Sym* sym = &syms[j];
      const char* current_name;

      if (sym->st_name == 0 || sym->st_shndx == SHN_UNDEF) {
        continue;
      }
      if (ELF64_ST_TYPE(sym->st_info) != STT_FUNC) {
        continue;
      }

      current_name = strtab + sym->st_name;
      if (strcmp(current_name, symbol_name) != 0) {
        continue;
      }

      file_offset = file_offset_from_vaddr(ehdr, sym->st_value);
      if (file_offset < 0) {
        munmap(data, size);
        return (int)file_offset;
      }

      *offset_out = (unsigned long)file_offset;
      munmap(data, size);
      return 0;
    }
  }

  munmap(data, size);
  return -ENOENT;
}

static struct bpf_link* attach_kprobe_with_fallback(struct bpf_program* prog,
                                                    const char* symbol_name, bool retprobe) {
  static const char* const openat_candidates[] = {
      "openat",
      "__x64_sys_openat",
      "__arm64_sys_openat",
      "do_sys_openat2",
  };
  struct bpf_kprobe_opts opts = {
      .sz = sizeof(opts),
      .retprobe = retprobe,
  };
  struct bpf_link* link;
  size_t index;

  if (strcmp(symbol_name, "openat") != 0) {
    return bpf_program__attach_kprobe_opts(prog, symbol_name, &opts);
  }

  for (index = 0; index < sizeof(openat_candidates) / sizeof(openat_candidates[0]); ++index) {
    long err;

    link = bpf_program__attach_kprobe_opts(prog, openat_candidates[index], &opts);
    err = libbpf_get_error(link);
    if (err == 0) {
      if (strcmp(openat_candidates[index], symbol_name) != 0) {
        fprintf(stderr, "kprobe symbol '%s' unavailable, attached to fallback '%s'\n", symbol_name,
                openat_candidates[index]);
      }
      return link;
    }
  }

  return NULL;
}

static struct bpf_link* attach_generic_probe(struct bpf_object* obj,
                                             const struct probe_spec* spec) {
  struct bpf_program* prog;

  prog = bpf_object__find_program_by_name(obj, spec->program_name);
  if (!prog) {
    fprintf(stderr, "unable to find BPF program '%s'\n", spec->program_name);
    return NULL;
  }

  if (spec->type == PROBE_TARGET_KPROBE) {
    return attach_kprobe_with_fallback(prog, spec->symbol_name, spec->retprobe);
  }

  {
    struct bpf_uprobe_opts opts = {
        .sz = sizeof(opts),
        .retprobe = spec->retprobe,
    };
    unsigned long offset = 0;
    int err = resolve_symbol_offset(spec->binary_path, spec->symbol_name, &offset);
    if (err != 0) {
      fprintf(stderr, "failed to resolve %s in %s: %s\n", spec->symbol_name, spec->binary_path,
              strerror(-err));
      return NULL;
    }

    printf("resolved %s in %s to file offset 0x%lx\n", spec->symbol_name, spec->binary_path,
           offset);
    return bpf_program__attach_uprobe_opts(prog, spec->pid, spec->binary_path, offset, &opts);
  }
}

static int attach_or_report(struct bpf_object* obj, const struct probe_spec* spec,
                            struct bpf_link** link_out) {
  struct bpf_link* link;
  long err;

  link = attach_generic_probe(obj, spec);
  if (!link) {
    return -EINVAL;
  }

  err = libbpf_get_error(link);
  if (err != 0) {
    fprintf(stderr, "attach failed for %s: %s\n", spec->symbol_name, strerror((int)-err));
    *link_out = NULL;
    return (int)err;
  }

  *link_out = link;
  return 0;
}

static int populate_config_map(struct probe_attach_generic_bpf* skel,
                               const struct probe_spec* specs, size_t spec_count) {
  int map_fd;
  size_t index;

  map_fd = bpf_map__fd(skel->maps.arg_configs);
  if (map_fd < 0) {
    fprintf(stderr, "failed to get arg_configs map fd\n");
    return -EINVAL;
  }

  for (index = 0; index < spec_count; ++index) {
    const struct probe_spec* spec = &specs[index];
    int err;

    err = bpf_map_update_elem(map_fd, &spec->function_id, &spec->config, BPF_ANY);
    if (err != 0) {
      err = -errno;
      fprintf(stderr, "failed to populate arg config for %s: %s\n", spec->display_name,
              strerror(-err));
      return err;
    }
  }

  return 0;
}

static int find_shared_object_path(const char* library_name, const char* symbol_name, char* buffer,
                                   size_t buffer_size) {
  Dl_info info;
  void* handle;
  void* symbol_address;

  handle = dlopen(library_name, RTLD_LAZY | RTLD_LOCAL);
  if (!handle) {
    return -ENOENT;
  }

  symbol_address = dlsym(handle, symbol_name);
  if (!symbol_address) {
    dlclose(handle);
    return -ENOENT;
  }

  if (dladdr(symbol_address, &info) == 0 || !info.dli_fname) {
    dlclose(handle);
    return -ENOENT;
  }
  if (strlen(info.dli_fname) + 1 > buffer_size) {
    dlclose(handle);
    return -ENAMETOOLONG;
  }

  snprintf(buffer, buffer_size, "%s", info.dli_fname);
  dlclose(handle);
  return 0;
}

static void bump_memlock_rlimit(void) {
  struct rlimit limit = {
      .rlim_cur = RLIM_INFINITY,
      .rlim_max = RLIM_INFINITY,
  };

  if (setrlimit(RLIMIT_MEMLOCK, &limit) != 0) {
    fprintf(stderr, "warning: failed to raise RLIMIT_MEMLOCK: %s\n", strerror(errno));
  }
}

static int trigger_open_path(void) {
  int fd;

  fd = open("/dev/null", O_RDONLY);
  if (fd < 0) {
    return -errno;
  }

  close(fd);
  return 0;
}

int main(int argc, char** argv) {
  struct app_context app;
  char libc_path[PATH_MAX];
  static const unsigned int kprobe_arg_index[MAX_CAPTURE_ARGS] = {0, 2};
  static const unsigned int kprobe_arg_num_bytes[MAX_CAPTURE_ARGS] = {sizeof(int), sizeof(int)};
  static const unsigned int kprobe_arg_is_pointer[MAX_CAPTURE_ARGS] = {0, 0};
  static const char* const kprobe_arg_label[MAX_CAPTURE_ARGS] = {"dfd", "flags", NULL};
  static const char* const kprobe_arg_c_type[MAX_CAPTURE_ARGS] = {"int", "int", NULL};
  static const unsigned int uprobe_arg_index[MAX_CAPTURE_ARGS] = {0, 1};
  static const unsigned int uprobe_arg_num_bytes[MAX_CAPTURE_ARGS] = {MAX_CAPTURE_BYTES,
                                                                      sizeof(int)};
  static const unsigned int uprobe_arg_is_pointer[MAX_CAPTURE_ARGS] = {1, 0};
  static const char* const uprobe_arg_label[MAX_CAPTURE_ARGS] = {"pathname", "flags", NULL};
  static const char* const uprobe_arg_c_type[MAX_CAPTURE_ARGS] = {"const char *", "int", NULL};
  const char* kernel_symbol = "openat";
  const char* user_symbol = "open";
  struct probe_attach_generic_bpf* skel;
  struct ring_buffer* rb = NULL;
  struct bpf_link* links[2] = {NULL, NULL};
  struct probe_spec specs[2];
  int err;
  int i;

  if (argc > 1) {
    kernel_symbol = argv[1];
  }
  if (argc > 2) {
    user_symbol = argv[2];
  }

  err = find_shared_object_path("libc.so.6", user_symbol, libc_path, sizeof(libc_path));
  if (err != 0) {
    fprintf(stderr, "failed to discover libc path: %s\n", strerror(-err));
    return 1;
  }

  libbpf_set_print(libbpf_print_fn);
  bump_memlock_rlimit();
  skel = probe_attach_generic_bpf__open_and_load();
  if (!skel) {
    fprintf(stderr, "failed to open and load BPF skeleton\n");
    return 1;
  }

  specs[0] = (struct probe_spec){
      .type = PROBE_TARGET_KPROBE,
      .function_id = 1,
      .program_name = "trace_kernel",
      .symbol_name = kernel_symbol,
      .display_name = kernel_symbol,
      .binary_path = NULL,
      .retprobe = false,
      .pid = 0,
  };
  specs[1] = (struct probe_spec){
      .type = PROBE_TARGET_UPROBE,
      .function_id = 2,
      .program_name = "trace_user",
      .symbol_name = user_symbol,
      .display_name = user_symbol,
      .binary_path = libc_path,
      .retprobe = false,
      .pid = getpid(),
  };

  init_capture_config(&specs[0].config, specs[0].function_id, PROBE_KIND_KPROBE,
                      specs[0].display_name, 2, kprobe_arg_index, kprobe_arg_num_bytes,
                      kprobe_arg_is_pointer, kprobe_arg_label, kprobe_arg_c_type);
  init_capture_config(&specs[1].config, specs[1].function_id, PROBE_KIND_UPROBE,
                      specs[1].display_name, 2, uprobe_arg_index, uprobe_arg_num_bytes,
                      uprobe_arg_is_pointer, uprobe_arg_label, uprobe_arg_c_type);

  app.specs = specs;
  app.spec_count = 2;

  err = populate_config_map(skel, specs, 2);
  if (err != 0) {
    goto cleanup;
  }

  for (i = 0; i < 2; ++i) {
    err = attach_or_report(skel->obj, &specs[i], &links[i]);
    if (err != 0) {
      goto cleanup;
    }
  }

  rb = ring_buffer__new(bpf_map__fd(skel->maps.events), handle_event, &app, NULL);
  if (!rb) {
    err = -ENOMEM;
    fprintf(stderr, "failed to create ring buffer\n");
    goto cleanup;
  }

  printf("attached kprobe to %s and uprobe to %s:%s\n", kernel_symbol, libc_path, user_symbol);

  err = trigger_open_path();
  if (err != 0) {
    fprintf(stderr, "failed to trigger open path: %s\n", strerror(-err));
    goto cleanup;
  }

  for (i = 0; i < 20 && seen_events < 2; ++i) {
    err = ring_buffer__poll(rb, 100);
    if (err == -EINTR) {
      err = 0;
      break;
    }
    if (err < 0) {
      fprintf(stderr, "ring buffer polling failed: %s\n", strerror(-err));
      goto cleanup;
    }
  }

  if (seen_events < 2) {
    fprintf(stderr, "expected 2 events but only observed %d\n", seen_events);
    err = -ENOENT;
    goto cleanup;
  }

  err = 0;

cleanup:
  ring_buffer__free(rb);
  for (i = 0; i < 2; ++i) {
    bpf_link__destroy(links[i]);
  }
  probe_attach_generic_bpf__destroy(skel);
  return err == 0 ? 0 : 1;
}
