// SPDX-License-Identifier: MIT

// Shared contract between the client owning the DPA clock anchor and the dpa_telemetry
// plugin: the client publishes its fit through a seqlock in an mmap'd file, the plugin
// reads it to stamp CLOCK_MONOTONIC events onto the global epoch. One origin per device,
// so any process's fit applies to every DPA event on that device.

#ifndef DATACRUMBS_UTILS_COMMON_DPA_ANCHOR_SNAPSHOT_H
#define DATACRUMBS_UTILS_COMMON_DPA_ANCHOR_SNAPSHOT_H

#include <stdint.h>

#define DC_DPA_ANCHOR_MAGIC 0x44434441u  // "DCDA"
#define DC_DPA_ANCHOR_SNAPSHOT_PATH "/dev/shm/dc_dpa_anchor.snapshot"

struct dc_dpa_anchor_snapshot {
  uint32_t magic;
  uint32_t seq;  // odd = write in progress, reader retries
  uint32_t valid;
  uint32_t n;              // anchors in the fit
  uint64_t anchor_dpa_us;  // DPA clock at the fit's origin
  int64_t to_mono_ns;      // CLOCK_MONOTONIC ns minus anchor_dpa_us * 1000, at the origin
  int64_t skew_ppb;        // DPA rate error against CLOCK_MONOTONIC
  uint64_t err_ns;         // bracket error of the latest anchor
  uint64_t written_mono_ns;
};

#endif  // DATACRUMBS_UTILS_COMMON_DPA_ANCHOR_SNAPSHOT_H
