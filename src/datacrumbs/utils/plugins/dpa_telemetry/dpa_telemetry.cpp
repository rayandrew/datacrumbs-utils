// Plugin: sample the DPA cores' own per-thread counters onto the trace timeline. GOTCHA rewrites
// the GOT of a host process, so a kernel on the DPA cores has no host call to intercept: the launch
// is traced, the execution is not.
//
// A plugin and not a client shim: the API needs privilege the shims do not have, counter_start acts
// on the whole device so several traced processes would fight over one switch, and the DPA
// processes are not the traced host processes, so node scope is the honest scope.
//
// The device counts one way at a time; with cumulative counters running, starting the event tracer
// returns BAD_STATE. So DATACRUMBS_DPA_MODE picks one:
//
//   counters  per-thread cycle and instruction deltas (default)
//   events    schedule in and out, the device's own activity trace
//
// Loaded via DATACRUMBS_PLUGINS. Ticks on DATACRUMBS_TELEMETRY_INTERVAL_MS with every other
// periodic sampler.

#include <datacrumbs/common/logging.h>
#include <datacrumbs/common/plugin_api.h>
#include <datacrumbs/utils/common/configuration_manager.h>
#include <doca_dev.h>
#include <doca_error.h>
#include <doca_telemetry_dpa.h>

#include <ctime>
#include <map>
#include <string>
#include <utility>
#include <vector>

namespace {

struct Prev {
  unsigned long long cycles, instructions, time, executions;
};

struct State {
  struct doca_dev* dev = nullptr;
  struct doca_telemetry_dpa* dpa = nullptr;
  uint64_t event_id = 0;        // per-thread counter deltas
  uint64_t sched_event_id = 0;  // schedule in and out, the device's own event trace
  bool counters_started = false;
  bool perf_started = false;
  uint64_t last_event_us = 0;      // the event read returns the whole buffer each time, not a drain
  bool want_events = false;        // DATACRUMBS_DPA_MODE=events
  uint64_t dpa_ticks_per_sec = 0;  // for turning the device's tick stamps into a duration
  // Not 0: that asks for the process and thread literally numbered zero, which silently dropped one
  // of two DPA processes and labelled every record thread 0.
  uint32_t all_proc = 0xffffffffu;
  uint32_t all_thread = 0xffffffffu;
  std::map<uint32_t, std::string> thread_name;  // dpa_thread_id -> name the device reports
  std::map<uint32_t, uint32_t> thread_proc;     // dpa_thread_id -> owning dpa process
  // Per (process, thread), so a thread appearing midway is not charged what it did before.
  std::map<std::pair<uint32_t, uint32_t>, Prev> prev;
};

State g_state;

unsigned long long mono_ns() {
  timespec t;
  clock_gettime(CLOCK_MONOTONIC, &t);
  return static_cast<unsigned long long>(t.tv_sec) * 1000000000ull +
         static_cast<unsigned long long>(t.tv_nsec);
}

/// Open the first device that offers DPA telemetry. False when none does, which is normal on a card
/// without a DPA rather than an error.
bool open_device() {
  struct doca_devinfo** list = nullptr;
  uint32_t n = 0;
  if (doca_devinfo_create_list(&list, &n) != DOCA_SUCCESS) return false;
  for (uint32_t i = 0; i < n; i++) {
    if (doca_telemetry_dpa_cap_is_supported(list[i]) != DOCA_SUCCESS) continue;
    if (doca_dev_open(list[i], &g_state.dev) == DOCA_SUCCESS) break;
  }
  doca_devinfo_destroy_list(list);
  return g_state.dev != nullptr;
}

/// One tick: read every DPA thread's cumulative counters and emit a record each. The list is sized
/// every tick, since a buffer sized on the first would silently drop threads appearing later.
void sample(const datacrumbs::PluginEmit& emit) {
  if (g_state.dpa == nullptr) return;

  // Counters have to be started before they count; a first reading reports every counter at zero,
  // which is not evidence that nothing ran. Retried every tick because at registration there is
  // usually no DPA process yet and the start fails with DOCA_ERROR_DRIVER.
  if (g_state.want_events) {
    if (!g_state.perf_started) {
      doca_error_t e = doca_telemetry_dpa_counter_start(
          g_state.dpa, g_state.all_proc, DOCA_TELEMETRY_DPA_COUNTER_TYPE_EVENT_TRACER);
      if (e != DOCA_SUCCESS) {
        // The arm survives the process that made it, so a killed run leaves the device armed and
        // every later start refused. Stopping first is the only way back.
        doca_telemetry_dpa_counter_stop(g_state.dpa, g_state.all_proc,
                                        DOCA_TELEMETRY_DPA_COUNTER_TYPE_EVENT_TRACER);
        e = doca_telemetry_dpa_counter_start(g_state.dpa, g_state.all_proc,
                                             DOCA_TELEMETRY_DPA_COUNTER_TYPE_EVENT_TRACER);
      }
      if (e == DOCA_SUCCESS) {
        g_state.perf_started = true;
        DC_LOG_INFO("dpa telemetry: schedule event tracer started");
      }
    }
    return;  // the device counts one way at a time; cumulative would be refused
  }
  if (!g_state.counters_started) {
    if (doca_telemetry_dpa_counter_start(g_state.dpa, g_state.all_proc,
                                         DOCA_TELEMETRY_DPA_COUNTER_TYPE_CUMULATIVE_EVENT) ==
        DOCA_SUCCESS) {
      g_state.counters_started = true;
      DC_LOG_INFO("dpa telemetry: cumulative counters started");
    }
  }

  uint32_t size = 0;
  if (doca_telemetry_dpa_get_cumul_samples_size(g_state.dpa, g_state.all_proc, g_state.all_thread,
                                                &size) != DOCA_SUCCESS ||
      size == 0) {
    return;
  }
  std::vector<doca_telemetry_dpa_cumul_info_t> info(size);
  uint32_t got = size;
  if (doca_telemetry_dpa_read_cumul_info_list(g_state.dpa, g_state.all_proc, g_state.all_thread,
                                              &got, info.data()) != DOCA_SUCCESS) {
    return;
  }
  const unsigned long long now = mono_ns();
  for (uint32_t i = 0; i < got && i < size; i++) {
    const std::pair<uint32_t, uint32_t> key{info[i].dpa_process_id, info[i].dpa_thread_id};
    const Prev cur{info[i].cycles, info[i].instructions, info[i].time, info[i].num_executions};
    const auto seen = g_state.prev.find(key);
    g_state.prev[key] = cur;
    // Per-interval deltas, matching every other counter in this trace: two conventions in one file
    // are indistinguishable to a reader. A thread's first tick is skipped rather than emitted as
    // its lifetime total. The device totals ride along so nothing is lost by differencing.
    if (seen == g_state.prev.end()) continue;
    const Prev& old_v = seen->second;
    if (cur.cycles < old_v.cycles) continue;  // counters were reset under us; re-prime instead
    auto* args = new DataCrumbsArgs();
    (*args)["dpa.process"] = static_cast<unsigned long long>(info[i].dpa_process_id);
    (*args)["dpa.thread"] = static_cast<unsigned long long>(info[i].dpa_thread_id);
    (*args)["dpa.cycles"] = cur.cycles - old_v.cycles;
    (*args)["dpa.instructions"] = cur.instructions - old_v.instructions;
    (*args)["dpa.time_ticks"] = cur.time - old_v.time;
    (*args)["dpa.executions"] = cur.executions - old_v.executions;
    (*args)["dpa.cycles_total"] = cur.cycles;
    (*args)["dpa.instructions_total"] = cur.instructions;
    emit(g_state.event_id, now, args);
  }
}

/// Re-read which DPA processes and threads the device knows about, so a schedule record carries a
/// name not a bare id. Per tick, or a workload starting after the sampler stays nameless.
void refresh_names() {
  uint32_t bytes = 0;
  if (doca_telemetry_dpa_get_thread_list_size(g_state.dpa, g_state.all_proc, g_state.all_thread,
                                              &bytes) != DOCA_SUCCESS ||
      bytes < sizeof(doca_telemetry_dpa_thread_info_t)) {
    return;
  }
  // The device sizes this for every thread it could host: 1.8 MB against a list of one or two
  // entries. Kept and only grown, rather than zeroed 10 times a second for nothing.
  static std::vector<doca_telemetry_dpa_thread_info_t> tl;
  const uint32_t cap = bytes / static_cast<uint32_t>(sizeof(doca_telemetry_dpa_thread_info_t));
  if (tl.size() < cap) tl.resize(cap);
  uint32_t got = cap;
  if (doca_telemetry_dpa_read_thread_list(g_state.dpa, g_state.all_proc, g_state.all_thread, &got,
                                          tl.data()) != DOCA_SUCCESS) {
    return;
  }
  if (got > cap) got = cap;
  for (uint32_t i = 0; i < got; i++) {
    g_state.thread_proc[tl[i].dpa_thread_id] = tl[i].dpa_process_id;
    // The device leaves the name empty unless the application set one, so empty means absent.
    if (tl[i].thread_name[0] != '\0')
      g_state.thread_name[tl[i].dpa_thread_id] =
          std::string(tl[i].thread_name, strnlen(tl[i].thread_name, sizeof(tl[i].thread_name)));
  }
}

/// One tick of the device's own event trace: every schedule in and out since the last read. A
/// schedule-in and the schedule-out after it bracket a DPA thread's occupancy of one execution
/// unit, and are matched here into one record with a duration.
///
/// Three things the header claims that this device does not do, each silently yielding an empty
/// trace if believed:
///
///   type is never populated, so every record reads as EMPTY_SAMPLE. Pairing is by adjacency
///   instead: records arrive strictly in-then-out and the pair counter increments once per pair.
///
///   eu_id holds no execution unit. The 16 bits at offset 24 are a big-endian counter advancing by
///   one per pair, measured as delta 1 across all 2309 transitions of a 2310-record trace. Read
///   little-endian as declared it looks like a unit wandering 241-243, which is its low byte.
///
///   get_perf_event_samples_size returns bytes, not a count, and the read returns the whole buffer
///   from the start every time, so already-emitted records are skipped by timestamp.
void sample_events(const datacrumbs::PluginEmit& emit) {
  if (g_state.dpa == nullptr || !g_state.perf_started) return;

  static int diag = 0;
  uint32_t bytes = 0;
  const doca_error_t szerr = doca_telemetry_dpa_get_perf_event_samples_size(g_state.dpa, &bytes);
  if (szerr != DOCA_SUCCESS || bytes < sizeof(doca_telemetry_dpa_event_sample_t)) {
    if (diag++ < 3) DC_LOG_INFO("dpa events: size=%s bytes=%u", doca_error_get_name(szerr), bytes);
    return;
  }
  const uint32_t cap = bytes / static_cast<uint32_t>(sizeof(doca_telemetry_dpa_event_sample_t));
  std::vector<doca_telemetry_dpa_event_sample_t> ev(cap);
  uint32_t got = cap;
  const doca_error_t rderr = doca_telemetry_dpa_read_perf_event_list(
      g_state.dpa, g_state.all_proc, g_state.all_thread, &got, ev.data());
  if (rderr != DOCA_SUCCESS) {
    if (diag++ < 3) DC_LOG_INFO("dpa events: read=%s", doca_error_get_name(rderr));
    return;
  }
  if (got > cap) got = cap;
  refresh_names();
  unsigned emitted = 0;

  // Not a fixed stride: a read can begin on a schedule-out whose schedule-in went out with the
  // previous read, and pairing blindly from there mismatches everything after. Both halves of a
  // pair carry the same eu_id word, so a mismatch means the pair starts one record later.
  for (uint32_t i = 0; i + 1 < got;) {
    const auto& in = ev[i];
    const auto& out = ev[i + 1];
    if (in.eu_id != out.eu_id || out.timestamp < in.timestamp) {
      i++;
      continue;
    }
    i += 2;
    if (in.timestamp <= g_state.last_event_us) continue;

    auto* args = new DataCrumbsArgs();
    (*args)["dpa.thread"] = static_cast<unsigned long long>(in.dpa_thread_id);
    const auto proc = g_state.thread_proc.find(in.dpa_thread_id);
    if (proc != g_state.thread_proc.end())
      (*args)["dpa.process"] = static_cast<unsigned long long>(proc->second);
    const auto name = g_state.thread_name.find(in.dpa_thread_id);
    if (name != g_state.thread_name.end()) (*args)["dpa.thread_name"] = name->second;
    (*args)["dpa.sample_id"] = static_cast<unsigned long long>(__builtin_bswap16(in.eu_id));
    (*args)["dpa.cycles"] = static_cast<unsigned long long>(out.cycles - in.cycles);
    (*args)["dpa.instructions"] =
        static_cast<unsigned long long>(out.instructions - in.instructions);
    (*args)["dpa.dur_us"] = static_cast<unsigned long long>(out.timestamp - in.timestamp);
    // Kept as it came: this is the DPA clock, not the host's, and converting it here on an
    // unverified relation is worse than leaving the join to analysis that sees both.
    (*args)["dpa.timestamp_us"] = static_cast<unsigned long long>(in.timestamp);
    emit(g_state.sched_event_id, mono_ns(), args);
    g_state.last_event_us = in.timestamp;
    emitted++;
  }
  if (diag++ < 5)
    DC_LOG_INFO("dpa events: cap=%u got=%u emitted=%u watermark=%llu", cap, got, emitted,
                (unsigned long long)g_state.last_event_us);
}

}  // namespace

// A counter stays armed after the process that armed it exits, so leaving one running fails the
// next run's counter_start. Best effort: this does not run on a kill, hence the stop-first on arm.
__attribute__((destructor)) void dpa_telemetry_unload() {
  if (g_state.dpa == nullptr) return;
  if (g_state.perf_started)
    doca_telemetry_dpa_counter_stop(g_state.dpa, g_state.all_proc,
                                    DOCA_TELEMETRY_DPA_COUNTER_TYPE_EVENT_TRACER);
  if (g_state.counters_started)
    doca_telemetry_dpa_counter_stop(g_state.dpa, g_state.all_proc,
                                    DOCA_TELEMETRY_DPA_COUNTER_TYPE_CUMULATIVE_EVENT);
}

extern "C" bool datacrumbs_plugin_register(const datacrumbs::PluginApi* api) {
  if (api == nullptr || api->abi_version != datacrumbs::PluginApi::kAbiVersion) return false;
  if (api->register_sampler == nullptr || api->register_event_name == nullptr) return false;

  if (!open_device()) {
    DC_LOG_WARN("dpa telemetry plugin: no device offers DPA telemetry; not sampling");
    return true;  // a card without a DPA is not a failure to load
  }
  if (doca_telemetry_dpa_create(g_state.dev, &g_state.dpa) != DOCA_SUCCESS) {
    DC_LOG_WARN("dpa telemetry plugin: could not create telemetry; not sampling");
    return true;
  }
  // Before start, not after: the device sizes its event buffer at start, and setting the size
  // afterwards returns BAD_STATE, leaving the tracer nowhere to write.
  const uint32_t samples = datacrumbs::ConfigurationManager::runtime().dpa_event_samples;
  if (doca_telemetry_dpa_set_max_perf_event_samples(g_state.dpa, samples) != DOCA_SUCCESS)
    DC_LOG_WARN("dpa telemetry: event buffer not sized; schedule events may be unavailable");
  if (doca_telemetry_dpa_start(g_state.dpa) != DOCA_SUCCESS) {
    DC_LOG_WARN("dpa telemetry plugin: could not start telemetry; not sampling");
    return true;
  }

  const struct doca_devinfo* info = doca_dev_as_devinfo(g_state.dev);
  if (doca_telemetry_dpa_get_all_process_id(info, &g_state.all_proc) != DOCA_SUCCESS ||
      doca_telemetry_dpa_get_all_thread_id(info, &g_state.all_thread) != DOCA_SUCCESS) {
    DC_LOG_WARN("dpa telemetry: device did not report its all-process selector; using 0xffffffff");
  }

  g_state.want_events = datacrumbs::ConfigurationManager::runtime().dpa_mode_events;
  g_state.event_id = api->register_event_name("dpa", "dpa_thread", "dpa");
  g_state.sched_event_id = api->register_event_name("dpa", "dpa_schedule", "dpa");
  const unsigned int interval = datacrumbs::ConfigurationManager::runtime().telemetry_interval_ms;
  api->register_sampler(interval, sample);
  // Registered unconditionally: whether the tracer starts is decided per tick, once a DPA process
  // exists.
  api->register_sampler(interval, sample_events);
  DC_LOG_INFO("dpa telemetry plugin: sampling DPA %s every %u ms",
              g_state.want_events ? "schedule events" : "thread counters", interval);
  return true;
}
