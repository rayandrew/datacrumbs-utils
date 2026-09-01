// Plugin: sample the device's own diagnostic counters (doca_telemetry_diag) onto the timeline.
// These are the NIC's internal counters, not the host's view of it: physical port bytes, PCIe link
// bytes and stall time, PCIe read latency, the internal cache, and the completion engine's CQE
// counts. The completion engine count is exact - 1001 submitted DMA operations read back as 1001.
//
// A plugin and not a client shim: the API needs root, the counter list is applied device-wide so
// several traced processes would fight over one configuration, and the counters describe the whole
// device rather than any one traced process, so node scope is the honest scope.
//
// Loaded via DATACRUMBS_PLUGINS. Ticks on DATACRUMBS_TELEMETRY_INTERVAL_MS with every other
// periodic sampler. Groups from DATACRUMBS_DOCA_DIAG_GROUPS (comma-separated), default all.

#include <datacrumbs/common/logging.h>
#include <datacrumbs/common/plugin_api.h>
#include <datacrumbs/utils/common/configuration_manager.h>
#include <doca_dev.h>
#include <doca_error.h>
#include <doca_telemetry_diag.h>

#include <cstdint>
#include <cstdio>
#include <cstring>
#include <ctime>
#include <string>
#include <vector>

namespace {

// A data id is [group:16][counter:16][index:32]; the index selects a port, host, priority or PCIe
// link. Only index 0 is sampled: the other indices are the same counter on another port.
constexpr unsigned kIdCounterShift = 32;
constexpr unsigned kIdGroupShift = 48;

// Cumulative counters are reported as per-interval deltas, matching every other counter in this
// trace. A min or a max is not cumulative, so differencing it is meaningless: those ride along as
// the value the device reports.
enum class Kind { kCumulative, kGauge };

struct CounterDef {
  uint16_t counter;
  const char* name;
  Kind kind;
};

struct GroupDef {
  uint16_t group;
  const char* name;
  const CounterDef* counters;
  unsigned count;
};

// Names from the "List of Supported Data IDs" appendix of the DOCA Telemetry Diag guide. Gaps are
// the device's, not omissions: 0x1080 counters 2 and 3 and 0x10c0 counter 3 are documented but
// report unsupported on BlueField-3.
const CounterDef kPortRx[] = {
    {0x1, "bytes", Kind::kCumulative},
    {0x2, "priority_bytes", Kind::kCumulative},
    {0x3, "packets", Kind::kCumulative},
    {0x4, "priority_packets", Kind::kCumulative},
    {0x5, "discard_buf_packets", Kind::kCumulative},
    {0x6, "priority_pause_packets", Kind::kCumulative},
};

const CounterDef kHostRxBuffer[] = {
    {0x1, "discards", Kind::kCumulative},
};

const CounterDef kRxTransport[] = {
    {0x1, "host_pass_packets", Kind::kCumulative},
    {0x4, "port_ecn_packets", Kind::kCumulative},
    {0x5, "port_cnp_handled_packets", Kind::kCumulative},
};

const CounterDef kCompletionEngine[] = {
    {0x1, "global_rx_cqes", Kind::kCumulative},
    {0x2, "function_rx_cqes", Kind::kCumulative},
    {0x4, "global_tx_cqes", Kind::kCumulative},
    {0x5, "function_tx_cqes", Kind::kCumulative},
};

const CounterDef kTxTransport[] = {
    {0x1, "port_cnp_sent_packets", Kind::kCumulative},
    {0x2, "cc_deschedule_events", Kind::kCumulative},
};

const CounterDef kPortTx[] = {
    {0x1, "bytes", Kind::kCumulative},
    {0x2, "priority_bytes", Kind::kCumulative},
    {0x3, "packets", Kind::kCumulative},
    {0x4, "priority_packets", Kind::kCumulative},
    {0x5, "priority_pause_packets", Kind::kCumulative},
};

const CounterDef kPcieLink[] = {
    {0x1, "inbound_bytes", Kind::kCumulative},
    {0x2, "outbound_bytes", Kind::kCumulative},
    {0x3, "inbound_data_bytes", Kind::kCumulative},
    {0x4, "outbound_data_bytes", Kind::kCumulative},
    {0x5, "write_stall_no_posted_data_credits_ns", Kind::kCumulative},
    {0x6, "write_stall_no_posted_header_credits_ns", Kind::kCumulative},
    {0x7, "read_stall_no_non_posted_data_credits_ns", Kind::kCumulative},
    {0x8, "read_stall_no_non_posted_header_credits_ns", Kind::kCumulative},
    {0x9, "read_stall_no_completion_buffers_ns", Kind::kCumulative},
    {0xa, "tclass_read_stall_ordering_ns", Kind::kCumulative},
    {0xb, "latency_total_read_ns", Kind::kCumulative},
    {0xc, "latency_total_read_packets", Kind::kCumulative},
    {0xd, "latency_max_read_ns", Kind::kGauge},
    {0xe, "latency_min_read_ns", Kind::kGauge},
};

const CounterDef kIcmc[] = {
    {0x1, "request", Kind::kCumulative},
    {0x2, "hit", Kind::kCumulative},
    {0x3, "miss", Kind::kCumulative},
};

// Supported by the device but absent from the published appendix. Carried because it is real, and
// left unnamed because guessing a meaning is worse than admitting there is none; diag.raw_group
// says which group it is.
const CounterDef kUndocumented[] = {
    {0x4, "counter_0x4", Kind::kCumulative},
};

#define DC_GROUP(g, n, arr) \
  { (g), (n), (arr), sizeof(arr) / sizeof((arr)[0]) }

const GroupDef kGroups[] = {
    DC_GROUP(0x1020, "port_rx", kPortRx),
    DC_GROUP(0x1040, "host_rx_buffer", kHostRxBuffer),
    DC_GROUP(0x1080, "rx_transport", kRxTransport),
    DC_GROUP(0x10c0, "completion_engine", kCompletionEngine),
    DC_GROUP(0x1100, "tx_transport", kTxTransport),
    DC_GROUP(0x1140, "port_tx", kPortTx),
    DC_GROUP(0x1160, "pcie_link", kPcieLink),
    DC_GROUP(0x1180, "icmc", kIcmc),
    DC_GROUP(0x11a0, "undocumented", kUndocumented),
};

#undef DC_GROUP

constexpr unsigned kGroupCount = sizeof(kGroups) / sizeof(kGroups[0]);

// Device-side ring of 2^n samples. Enough that a late drain loses nothing, small enough that a
// stalled sampler does not sit on a large device buffer.
constexpr uint8_t kLogMaxSamples = 4;

struct Applied {
  const GroupDef* group;
  const CounterDef* counter;
  uint64_t id;
  uint64_t prev;
  bool primed;
};

struct State {
  struct doca_dev* dev = nullptr;
  struct doca_telemetry_diag* diag = nullptr;
  std::vector<Applied> applied;
  std::vector<uint64_t> event_id;  // one per group, indexed as kGroups
  std::vector<unsigned char> buffer;
  uint32_t sample_size = 0;   // bytes per sample, from the device rather than from sizeof
  uint32_t max_samples = 0;   // how many the buffer holds
  bool started = false;
};

State g_state;

unsigned long long mono_ns() {
  timespec t;
  clock_gettime(CLOCK_MONOTONIC, &t);
  return static_cast<unsigned long long>(t.tv_sec) * 1000000000ULL +
         static_cast<unsigned long long>(t.tv_nsec);
}

bool group_selected(const std::string& selection, const char* name) {
  if (selection.empty()) return true;
  for (std::size_t start = 0; start <= selection.size();) {
    std::size_t sep = selection.find(',', start);
    if (sep == std::string::npos) sep = selection.size();
    if (selection.compare(start, sep - start, name) == 0) return true;
    start = sep + 1;
  }
  return false;
}

/// Sample every applied counter and emit one record per group.
///
/// A sample is the outer format_0 struct: an 8-byte header then one value entry per applied id, in
/// the order the ids were applied. Sizing the buffer in entries and asking for a count in entries
/// overruns it by the number of ids, which is a crash, not a short read.
void sample(const datacrumbs::PluginEmit& emit) {
  if (g_state.diag == nullptr) return;
  if (!g_state.started) {
    if (doca_telemetry_diag_start(g_state.diag) != DOCA_SUCCESS) return;
    g_state.started = true;
    // Only valid once started: before that the device reports a size of zero and succeeds.
    const doca_error_t sz =
        doca_telemetry_diag_get_sample_size(g_state.diag, &g_state.sample_size);
    if (sz != DOCA_SUCCESS || g_state.sample_size == 0) {
      DC_LOG_INFO("doca diag: sample size unavailable (%s, %u bytes); sampling disabled",
                  doca_error_get_descr(sz), g_state.sample_size);
      doca_telemetry_diag_stop(g_state.diag);
      doca_telemetry_diag_destroy(g_state.diag);
      g_state.diag = nullptr;
      return;
    }
    g_state.max_samples = 1u << kLogMaxSamples;
    g_state.buffer.assign(static_cast<std::size_t>(g_state.sample_size) * g_state.max_samples, 0);
    uint64_t applied = 0;
    doca_telemetry_diag_get_sample_period(g_state.diag, &applied);
    DC_LOG_INFO("doca diag: sampling at %llu ns, %u bytes per sample",
                static_cast<unsigned long long>(applied), g_state.sample_size);
  }

  uint32_t got = 0;
  const doca_error_t rc = doca_telemetry_diag_query_counters(g_state.diag, g_state.buffer.data(),
                                                             g_state.max_samples, &got);
  // SKIPPED is success with a gap: the device filled its buffer before this drain. The data is
  // valid, so it is used; only the continuity is lost.
  if ((rc != DOCA_SUCCESS && rc != DOCA_ERROR_SKIPPED) || got == 0) return;

  // The device samples on its own period, so a tick can find several. They are cumulative, so the
  // newest alone carries the whole interval; the older ones would only re-derive the same total.
  const auto* s = reinterpret_cast<const doca_telemetry_diag_data_sample_format_0*>(
      g_state.buffer.data() + static_cast<std::size_t>(got - 1) * g_state.sample_size);
  const unsigned long long now = mono_ns();

  for (unsigned g = 0; g < kGroupCount; g++) {
    if (g_state.event_id[g] == 0) continue;
    DataCrumbsArgs* args = nullptr;
    for (std::size_t i = 0; i < g_state.applied.size(); i++) {
      Applied& a = g_state.applied[i];
      if (a.group != &kGroups[g]) continue;
      const uint64_t value = s->value[i].data_value;
      if (a.counter->kind == Kind::kGauge) {
        if (args == nullptr) args = new DataCrumbsArgs();
        (*args)[a.counter->name] = value;
        continue;
      }
      const bool primed = a.primed;
      const uint64_t prev = a.prev;
      a.prev = value;
      a.primed = true;
      // The first tick has nothing to difference against, and a counter that went backwards was
      // reset under us; either way re-prime rather than emit a lifetime total as an interval.
      if (!primed || value < prev) continue;
      if (args == nullptr) args = new DataCrumbsArgs();
      (*args)[a.counter->name] = value - prev;
    }
    if (args == nullptr) continue;
    (*args)["diag.group"] = std::string(kGroups[g].name);
    // The id as written in the vendor appendix, so a reader can look the group up. Decimal 4448 is
    // not findable; 0x1160 is.
    char raw[8];
    std::snprintf(raw, sizeof(raw), "0x%04x", kGroups[g].group);
    (*args)["diag.raw_group"] = std::string(raw);
    emit(g_state.event_id[g], now, args);
  }
}

void shutdown() {
  if (g_state.diag != nullptr) {
    if (g_state.started) doca_telemetry_diag_stop(g_state.diag);
    doca_telemetry_diag_destroy(g_state.diag);
    g_state.diag = nullptr;
  }
  if (g_state.dev != nullptr) {
    doca_dev_close(g_state.dev);
    g_state.dev = nullptr;
  }
}

}  // namespace

extern "C" bool datacrumbs_plugin_register(const datacrumbs::PluginApi* api) {
  if (api == nullptr || api->abi_version != datacrumbs::PluginApi::kAbiVersion) return false;
  if (api->register_sampler == nullptr || api->register_event_name == nullptr) return false;

  struct doca_devinfo** list = nullptr;
  uint32_t n = 0;
  if (doca_devinfo_create_list(&list, &n) != DOCA_SUCCESS) return false;
  for (uint32_t i = 0; i < n && g_state.dev == nullptr; i++)
    if (doca_telemetry_diag_cap_is_supported(list[i]) == DOCA_SUCCESS)
      doca_dev_open(list[i], &g_state.dev);
  doca_devinfo_destroy_list(list);
  if (g_state.dev == nullptr) {
    DC_LOG_INFO("doca diag: no device exposes diagnostic counters; plugin idle");
    return false;
  }

  // The second argument is a user data value, not the sample mode; the mode is a config field.
  doca_error_t rc = doca_telemetry_diag_create(g_state.dev, 1, &g_state.diag);
  if (rc != DOCA_SUCCESS) {
    DC_LOG_INFO("doca diag: create refused (%s); plugin idle", doca_error_get_descr(rc));
    shutdown();
    return false;
  }

  const std::string& selection = datacrumbs::ConfigurationManager::runtime().doca_diag_groups;
  std::vector<uint64_t> ids;
  for (unsigned g = 0; g < kGroupCount; g++) {
    if (!group_selected(selection, kGroups[g].name)) continue;
    for (unsigned k = 0; k < kGroups[g].count; k++) {
      const uint64_t id = (static_cast<uint64_t>(kGroups[g].group) << kIdGroupShift) |
                          (static_cast<uint64_t>(kGroups[g].counters[k].counter) << kIdCounterShift);
      ids.push_back(id);
      g_state.applied.push_back(Applied{&kGroups[g], &kGroups[g].counters[k], id, 0, false});
    }
  }
  if (ids.empty()) {
    DC_LOG_INFO("doca diag: no group selected by '%s'; plugin idle", selection.c_str());
    shutdown();
    return false;
  }

  // apply_config validates the whole configuration and rejects a partial one without naming the
  // field, so every field is set. ON_DEMAND samples on each query, which needs no period and no
  // sample buffer; it refuses the config unless both are zero.
  doca_telemetry_diag_set_max_num_data_ids(g_state.diag, static_cast<uint32_t>(ids.size()));
  doca_telemetry_diag_set_output_format(g_state.diag, DOCA_TELEMETRY_DIAG_OUTPUT_FORMAT_0);
  // REPETITIVE, not ON_DEMAND: on-demand forces a fresh device sample inside the call and costs
  // 2075 us, against 64 us to drain what the device already sampled. At a 50 ms tick that is the
  // difference between a 4% and a 0.1% duty cycle on the device being measured.
  const unsigned int interval = datacrumbs::ConfigurationManager::runtime().telemetry_interval_ms;
  doca_telemetry_diag_set_sample_mode(g_state.diag, DOCA_TELEMETRY_DIAG_SAMPLE_MODE_REPETITIVE);
  doca_telemetry_diag_set_sample_period(g_state.diag,
                                        static_cast<uint64_t>(interval) * 1000000ULL);
  doca_telemetry_diag_set_log_max_num_samples(g_state.diag, kLogMaxSamples);
  doca_telemetry_diag_set_sync_mode(g_state.diag, DOCA_TELEMETRY_DIAG_SYNC_MODE_NO_SYNC);
  doca_telemetry_diag_set_data_clear(g_state.diag, 0);
  doca_telemetry_diag_set_data_timestamp_source(g_state.diag,
                                                DOCA_TELEMETRY_DIAG_TIMESTAMP_SOURCE_FRC);
  rc = doca_telemetry_diag_apply_config(g_state.diag);
  if (rc != DOCA_SUCCESS) {
    // Needs root: without it the configuration is refused rather than the device hidden.
    DC_LOG_INFO("doca diag: apply_config refused (%s); plugin idle", doca_error_get_descr(rc));
    shutdown();
    return false;
  }

  uint64_t offending = 0;
  rc = doca_telemetry_diag_apply_counters_list_by_id(g_state.diag, ids.data(),
                                                     static_cast<uint32_t>(ids.size()), &offending);
  if (rc != DOCA_SUCCESS) {
    DC_LOG_INFO("doca diag: counter list refused (%s) at id 0x%llx; plugin idle",
                doca_error_get_descr(rc), static_cast<unsigned long long>(offending));
    shutdown();
    return false;
  }


  g_state.event_id.assign(kGroupCount, 0);
  for (unsigned g = 0; g < kGroupCount; g++) {
    if (!group_selected(selection, kGroups[g].name)) continue;
    g_state.event_id[g] = api->register_event_name("doca_diag", kGroups[g].name, "doca");
  }

  api->register_sampler(interval, sample);
  DC_LOG_INFO("doca diag: %zu counters over %u groups every %u ms", ids.size(), kGroupCount,
              interval);
  return true;
}
