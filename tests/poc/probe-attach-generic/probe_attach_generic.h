#ifndef PROBE_ATTACH_GENERIC_H
#define PROBE_ATTACH_GENERIC_H

#define TASK_COMM_LEN 16
#define FUNCTION_NAME_LEN 32
#define MAX_CAPTURE_ARGS 3
#define MAX_CAPTURE_BYTES 32
#define ARG_LABEL_LEN 24
#define ARG_CTYPE_LEN 24

enum probe_kind {
  PROBE_KIND_KPROBE = 1,
  PROBE_KIND_UPROBE = 2,
};

struct arg_capture_config {
  unsigned int function_id;
  unsigned int probe_kind;
  unsigned int arg_count;
  unsigned int arg_index[MAX_CAPTURE_ARGS];
  unsigned int arg_num_bytes[MAX_CAPTURE_ARGS];
  unsigned int arg_is_pointer[MAX_CAPTURE_ARGS];
  char function_name[FUNCTION_NAME_LEN];
  char arg_label[MAX_CAPTURE_ARGS][ARG_LABEL_LEN];
  char arg_c_type[MAX_CAPTURE_ARGS][ARG_CTYPE_LEN];
};

struct probe_event {
  unsigned int pid;
  unsigned int tid;
  unsigned int probe_kind;
  unsigned int function_id;
  unsigned int arg_count;
  char comm[TASK_COMM_LEN];
  char function_name[FUNCTION_NAME_LEN];
  unsigned long long args[MAX_CAPTURE_ARGS];
  unsigned int arg_data_len[MAX_CAPTURE_ARGS];
  unsigned int arg_data_status[MAX_CAPTURE_ARGS];
  unsigned char arg_data[MAX_CAPTURE_ARGS][MAX_CAPTURE_BYTES];
};

#endif
