// Node-scope plugin: counter_start acts on the whole device, so per-process scope
// would race between traced processes.
// The device counts one way at a time. Cumulative counters and the event tracer
// cannot run together, so DATACRUMBS_DPA_MODE selects one.

#include <datacrumbs/common/logging.h>
#include <datacrumbs/common/plugin_api.h>
#include <datacrumbs/utils/common/configuration_manager.h>
#include <datacrumbs/utils/common/constants.h>
#include <datacrumbs/utils/common/dpa_anchor_snapshot.h>
#include <doca_dev.h>
#include <doca_error.h>
#include <doca_telemetry_dpa.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <unistd.h>

#include <algorithm>
#include <cstdlib>
#include <ctime>
#include <iterator>
#include <map>
#include <mutex>
#include <set>
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
  // The event read returns the whole buffer each time, not a drain, and a buffer survives a re-arm.
  // Per thread: one watermark across threads drops another thread's older stamps read later.
  std::map<uint32_t, uint64_t> last_event_us;
  bool cut_done = false;
  unsigned long long pages_flipped = 0;  // re-arms on a full event page, for the stop log
  bool want_events = false;              // DATACRUMBS_DPA_MODE=events
  uint64_t dpa_ticks_per_sec = 0;        // for turning the device's tick stamps into a duration
  // Not 0: that asks for the process and thread literally numbered zero, which silently dropped one
  // of two DPA processes and labelled every record thread 0.
  uint32_t all_proc = 0xffffffffu;
  uint32_t all_thread = 0xffffffffu;
  std::map<uint32_t, std::string> thread_name;  // dpa_thread_id -> name the device reports
  std::map<uint32_t, uint32_t> thread_proc;     // dpa_thread_id -> owning dpa process
  std::map<uint32_t, std::string> proc_name;    // dpa_process_id -> name the device reports
  // The event tracer arms the processes that exist when it starts. A process that appears later
  // is not traced until the tracer is re-armed, so the set is compared every tick.
  std::set<uint32_t> procs;
  std::set<uint32_t> armed_procs;
  std::set<uint32_t> threads;  // same for threads: one created after the arm is not traced
  std::set<uint32_t> armed_threads;
  // Per (process, thread), so a thread appearing midway is not charged what it did before.
  std::map<std::pair<uint32_t, uint32_t>, Prev> prev;
};

State g_state;
// The server runs each registered sampler on its own thread; both samplers here read and write
// g_state, and refresh_names() from two threads corrupted the heap (core, 2026-09-08).
std::mutex g_mu;

unsigned long long mono_ns() {
  timespec t;
  clock_gettime(CLOCK_MONOTONIC, &t);
  return static_cast<unsigned long long>(t.tv_sec) * 1000000000ull +
         static_cast<unsigned long long>(t.tv_nsec);
}

void refresh_names();
bool is_anchor_process(uint32_t dpa_process_id);

/// The anchor fit a traced client published (dpa_anchor_snapshot.h). Opened lazily and retried,
/// because the client that writes it starts after the server.
struct AnchorSnap {
  const dc_dpa_anchor_snapshot* map = nullptr;
  unsigned long long next_try_ns = 0;
};
AnchorSnap g_snap;

bool read_anchor(dc_dpa_anchor_snapshot& out) {
  if (g_snap.map == nullptr) {
    const unsigned long long now = mono_ns();
    if (now < g_snap.next_try_ns) return false;
    g_snap.next_try_ns = now + 5'000'000'000ull;
    const int fd = ::open(DC_DPA_ANCHOR_SNAPSHOT_PATH, O_RDONLY);
    if (fd < 0) return false;
    void* p = ::mmap(nullptr, sizeof(dc_dpa_anchor_snapshot), PROT_READ, MAP_SHARED, fd, 0);
    ::close(fd);
    if (p == MAP_FAILED) return false;
    g_snap.map = static_cast<const dc_dpa_anchor_snapshot*>(p);
  }
  for (int attempt = 0; attempt < 8; ++attempt) {
    const uint32_t s1 = __atomic_load_n(&g_snap.map->seq, __ATOMIC_ACQUIRE);
    if (s1 & 1u) continue;
    out = *g_snap.map;
    __atomic_thread_fence(__ATOMIC_ACQUIRE);
    if (__atomic_load_n(&g_snap.map->seq, __ATOMIC_ACQUIRE) == s1)
      return out.magic == DC_DPA_ANCHOR_MAGIC && out.valid != 0;
  }
  return false;
}

/// The DPA clock at a CLOCK_MONOTONIC instant, through the published fit. Used to cut stale
/// events: the device keeps a per-process cyclic buffer, process ids are reused, and a read returns
/// whatever the buffer holds, including events from hours before the tracer was armed.
uint64_t mono_to_dpa_us(const dc_dpa_anchor_snapshot& s, unsigned long long mono_ns) {
  const long long dpa_ns = static_cast<long long>(mono_ns) - s.to_mono_ns;
  return static_cast<uint64_t>(dpa_ns / 1000LL);
}

/// After an arm, whatever the buffer already holds is from before it: the newest such stamp is the
/// watermark. From the device, not from a clock estimate: an estimate ahead of the device's own
/// stamps dropped every event of a run as stale.
void cut_stale_events() {
  uint32_t bytes = 0;
  if (doca_telemetry_dpa_get_perf_event_samples_size(g_state.dpa, &bytes) != DOCA_SUCCESS ||
      bytes < sizeof(doca_telemetry_dpa_event_sample_t))
    return;
  std::vector<doca_telemetry_dpa_event_sample_t> ev(
      2 * (bytes / static_cast<uint32_t>(sizeof(doca_telemetry_dpa_event_sample_t))));
  uint32_t got = 0;
  if (doca_telemetry_dpa_read_perf_event_list(g_state.dpa, g_state.all_proc, g_state.all_thread,
                                              &got, ev.data()) != DOCA_SUCCESS)
    return;
  if (got > ev.size()) got = static_cast<uint32_t>(ev.size());
  for (uint32_t i = 0; i < got; i++) {
    uint64_t& w = g_state.last_event_us[ev[i].dpa_thread_id];
    if (ev[i].timestamp > w) w = ev[i].timestamp;
  }
  g_state.cut_done = true;
}

/// A DPA microsecond stamp on CLOCK_MONOTONIC through the published fit.
unsigned long long dpa_to_mono_ns(const dc_dpa_anchor_snapshot& s, uint64_t dpa_us) {
  const long long dpa_ns = static_cast<long long>(dpa_us) * 1000LL;
  const long long since = dpa_ns - static_cast<long long>(s.anchor_dpa_us) * 1000LL;
  const long long drift = static_cast<long long>(static_cast<double>(s.skew_ppb) * since / 1e9);
  return static_cast<unsigned long long>(dpa_ns + s.to_mono_ns + drift);
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
  std::lock_guard<std::mutex> lock(g_mu);

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
        refresh_names();
        g_state.armed_procs = g_state.procs;
        g_state.armed_threads = g_state.threads;
        if (!g_state.cut_done) cut_stale_events();
        DC_LOG_INFO("dpa telemetry: schedule event tracer started");
      }
    } else {
      refresh_names();
      // A re-arm empties the device's event buffers. A thread created just before a burst, as the
      // ping-pong does, then loses the burst to the re-arm its own appearance caused.
      const std::string& policy = datacrumbs::ConfigurationManager::runtime().dpa_rearm;
      const bool changed = policy == "off"       ? false
                           : policy == "process" ? g_state.procs != g_state.armed_procs
                                                 : (g_state.procs != g_state.armed_procs ||
                                                    g_state.threads != g_state.armed_threads);
      if (changed) {
        doca_telemetry_dpa_counter_stop(g_state.dpa, g_state.all_proc,
                                        DOCA_TELEMETRY_DPA_COUNTER_TYPE_EVENT_TRACER);
        const doca_error_t e = doca_telemetry_dpa_counter_start(
            g_state.dpa, g_state.all_proc, DOCA_TELEMETRY_DPA_COUNTER_TYPE_EVENT_TRACER);
        if (e == DOCA_SUCCESS) {
          g_state.armed_procs = g_state.procs;
          g_state.armed_threads = g_state.threads;
          // No cut here: the buffer keeps its content across a re-arm, and the burst that made a
          // thread appear is usually already in it.
          std::string who;
          for (const uint32_t p : g_state.procs) {
            const auto nm = g_state.proc_name.find(p);
            who +=
                std::to_string(p) + "=" + (nm == g_state.proc_name.end() ? "?" : nm->second) + " ";
          }
          for (const uint32_t t : g_state.threads) who += "t" + std::to_string(t) + " ";
          DC_LOG_INFO("dpa telemetry: event tracer re-armed for %zu process(es), %zu thread(s): %s",
                      g_state.procs.size(), g_state.threads.size(), who.c_str());
        }
      }
    }
    return;  // the device counts one way at a time; cumulative would be refused
  }
  // Like the event tracer, the counters cover the processes that exist when they start: a
  // process that appears later counts zero until they are re-armed. The workload always appears
  // after the server. Re-armed on a process change, not on a thread change.
  refresh_names();
  if (!g_state.counters_started || g_state.procs != g_state.armed_procs) {
    if (g_state.counters_started)
      doca_telemetry_dpa_counter_stop(g_state.dpa, g_state.all_proc,
                                      DOCA_TELEMETRY_DPA_COUNTER_TYPE_CUMULATIVE_EVENT);
    if (doca_telemetry_dpa_counter_start(g_state.dpa, g_state.all_proc,
                                         DOCA_TELEMETRY_DPA_COUNTER_TYPE_CUMULATIVE_EVENT) ==
        DOCA_SUCCESS) {
      g_state.counters_started = true;
      g_state.armed_procs = g_state.procs;
      DC_LOG_INFO("dpa telemetry: cumulative counters armed for %zu process(es)",
                  g_state.procs.size());
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
  refresh_names();  // needs proc_name filled before the loop below can exclude the anchor
  const unsigned long long now = mono_ns();
  for (uint32_t i = 0; i < got && i < size; i++) {
    // The DPA clock anchor is datacrumbs' own process, not the traced workload: it must never
    // appear in the trace it is helping to place on the global epoch.
    if (is_anchor_process(info[i].dpa_process_id)) continue;
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
  g_state.threads.clear();
  for (uint32_t i = 0; i < got; i++) {
    g_state.threads.insert(tl[i].dpa_thread_id);
    g_state.thread_proc[tl[i].dpa_thread_id] = tl[i].dpa_process_id;
    // The device leaves the name empty unless the application set one, so empty means absent.
    if (tl[i].thread_name[0] != '\0')
      g_state.thread_name[tl[i].dpa_thread_id] =
          std::string(tl[i].thread_name, strnlen(tl[i].thread_name, sizeof(tl[i].thread_name)));
  }

  uint32_t proc_bytes = 0;
  if (doca_telemetry_dpa_get_process_list_size(g_state.dpa, g_state.all_proc, &proc_bytes) !=
          DOCA_SUCCESS ||
      proc_bytes < sizeof(doca_telemetry_dpa_process_info_t)) {
    return;
  }
  static std::vector<doca_telemetry_dpa_process_info_t> pl;
  const uint32_t proc_cap =
      proc_bytes / static_cast<uint32_t>(sizeof(doca_telemetry_dpa_process_info_t));
  if (pl.size() < proc_cap) pl.resize(proc_cap);
  uint32_t proc_got = proc_cap;
  if (doca_telemetry_dpa_read_processes_list(g_state.dpa, g_state.all_proc, &proc_got, pl.data()) !=
      DOCA_SUCCESS) {
    return;
  }
  if (proc_got > proc_cap) proc_got = proc_cap;
  g_state.procs.clear();
  for (uint32_t i = 0; i < proc_got; i++) {
    g_state.procs.insert(pl[i].dpa_process_id);
    if (pl[i].process_name[0] != '\0')
      g_state.proc_name[pl[i].dpa_process_id] =
          std::string(pl[i].process_name, strnlen(pl[i].process_name, sizeof(pl[i].process_name)));
  }
  // Our anchor's process and threads come and go with each burst. In the arm set they re-armed the
  // tracer at every change, and a re-arm empties the device's event buffers, which lost the traced
  // program's events. Never armed by us, never traced.
  for (auto it = g_state.procs.begin(); it != g_state.procs.end();)
    it = is_anchor_process(*it) ? g_state.procs.erase(it) : std::next(it);
  for (auto it = g_state.threads.begin(); it != g_state.threads.end();) {
    const auto p = g_state.thread_proc.find(*it);
    const bool ours = p != g_state.thread_proc.end() && is_anchor_process(p->second);
    it = ours ? g_state.threads.erase(it) : std::next(it);
  }
}

/// The anchor names its own DPA process DATACRUMBS_DPA_ANCHOR_PROCESS_NAME (constants.h), shared
/// with the dpacc --app-name that produces it, so this never drifts out of sync with what actually
/// gets built. Unknown until refresh_names() has run at least once, in which case this reads as
/// not-the-anchor rather than blocking the first tick on a name lookup.
bool is_anchor_process(uint32_t dpa_process_id) {
  const auto it = g_state.proc_name.find(dpa_process_id);
  return it != g_state.proc_name.end() && it->second == DATACRUMBS_DPA_ANCHOR_PROCESS_NAME;
}

void read_process_events(const datacrumbs::PluginEmit& emit, uint32_t proc_id, uint32_t cap,
                         bool verbose);

/// One tick of the device's own event trace: pairs each schedule-in with the schedule-out after
/// it into one record with a duration. get_perf_event_samples_size returns bytes, not a count,
/// and a read returns the whole buffer from the start every time, so already-emitted records are
/// skipped by timestamp.
void sample_events(const datacrumbs::PluginEmit& emit) {
  if (g_state.dpa == nullptr || !g_state.perf_started) return;
  std::lock_guard<std::mutex> lock(g_mu);

  static int diag = 0;
  static const bool verbose = std::getenv("DATACRUMBS_DPA_EVENT_DEBUG") != nullptr;
  uint32_t bytes = 0;
  const doca_error_t szerr = doca_telemetry_dpa_get_perf_event_samples_size(g_state.dpa, &bytes);
  if (szerr != DOCA_SUCCESS || bytes < sizeof(doca_telemetry_dpa_event_sample_t)) {
    if (diag++ < 3 || verbose)
      DC_LOG_INFO("dpa events: size=%s bytes=%u", doca_error_get_name(szerr), bytes);
    return;
  }
  // The buffer is per process, and one read for every process hands back one process's page
  // and truncates the rest: with our anchor's process first, the traced program's page never
  // came. Read each process on its own; the size is per process, so this is the cap for one.
  const uint32_t cap =
      2 * (bytes / static_cast<uint32_t>(sizeof(doca_telemetry_dpa_event_sample_t)));
  refresh_names();
  std::set<uint32_t> procs = g_state.procs;
  for (const auto& [t, p] : g_state.thread_proc) procs.insert(p);
  for (const uint32_t proc : procs) read_process_events(emit, proc, cap, verbose);
}

void read_process_events(const datacrumbs::PluginEmit& emit, uint32_t proc_id, uint32_t cap,
                         bool verbose) {
  static int diag = 0;
  static std::vector<doca_telemetry_dpa_event_sample_t> ev;
  if (ev.size() < cap) ev.resize(cap);
  uint32_t got = 0;
  const doca_error_t rderr = doca_telemetry_dpa_read_perf_event_list(
      g_state.dpa, proc_id, g_state.all_thread, &got, ev.data());
  if (rderr != DOCA_SUCCESS) {
    if (diag++ < 3 || verbose)
      DC_LOG_INFO("dpa events: process %u read=%s", proc_id, doca_error_get_name(rderr));
    return;
  }
  if (got > cap) {
    DC_LOG_ERROR("dpa events: read returned %u samples into a buffer of %u; memory is corrupt", got,
                 cap);
    got = cap;
  }
  unsigned emitted = 0;
  uint64_t hi_sane = 0;
  for (uint32_t i = 0; i < got; i++)
    if (ev[i].timestamp < (1ull << 48) && ev[i].timestamp > hi_sane) hi_sane = ev[i].timestamp;

  // type is never populated, so pairing is by adjacency, not tag. Not a fixed stride either: a
  // read can begin on a schedule-out whose schedule-in went with the previous read, so pairing
  // blindly mismatches everything after; matching eu_id on both halves catches the offset.
  for (uint32_t i = 0; i + 1 < got;) {
    const auto& in = ev[i];
    const auto& out = ev[i + 1];
    if (in.eu_id != out.eu_id || out.timestamp < in.timestamp) {
      i++;
      continue;
    }
    i += 2;
    // A stamp far beyond every other is an unset entry, not a future event.
    if (in.timestamp > hi_sane) continue;
    uint64_t& mark = g_state.last_event_us[in.dpa_thread_id];
    if (in.timestamp <= mark) continue;
    const auto proc = g_state.thread_proc.find(in.dpa_thread_id);
    // Same exclusion as sample(): the anchor is datacrumbs' own DPA process, not the workload.
    if (proc != g_state.thread_proc.end() && is_anchor_process(proc->second) &&
        !datacrumbs::ConfigurationManager::runtime().dpa_keep_anchor)
      continue;

    auto* args = new DataCrumbsArgs();
    (*args)["dpa.thread"] = static_cast<unsigned long long>(in.dpa_thread_id);
    if (proc != g_state.thread_proc.end())
      (*args)["dpa.process"] = static_cast<unsigned long long>(proc->second);
    const auto name = g_state.thread_name.find(in.dpa_thread_id);
    if (name != g_state.thread_name.end()) (*args)["dpa.thread_name"] = name->second;
    // eu_id is not an execution unit: it is a big-endian pair counter (bswap16 undoes that),
    // measured as delta 1 across all 2309 transitions of a 2310-record trace.
    (*args)["dpa.sample_id"] = static_cast<unsigned long long>(__builtin_bswap16(in.eu_id));
    (*args)["dpa.cycles"] = static_cast<unsigned long long>(out.cycles - in.cycles);
    (*args)["dpa.instructions"] =
        static_cast<unsigned long long>(out.instructions - in.instructions);
    (*args)["dpa.dur_us"] = static_cast<unsigned long long>(out.timestamp - in.timestamp);
    // Raw DPA clock, kept so the analysis can refit post hoc with the anchors near the event.
    (*args)["dpa.timestamp_us"] = static_cast<unsigned long long>(in.timestamp);
    // ts is the event's own time when a client has published an anchor fit within five minutes,
    // else the sample time. The viewer reads ts only, so the difference is stated in dpa.clock.
    unsigned long long ts = mono_ns();
    const char* clock = "sample";
    dc_dpa_anchor_snapshot snap{};
    if (read_anchor(snap) && ts - snap.written_mono_ns < 300'000'000'000ull) {
      ts = dpa_to_mono_ns(snap, in.timestamp);
      clock = "anchored";
      (*args)["dpa.anchor_err_ns"] = static_cast<unsigned long long>(snap.err_ns);
    }
    (*args)["dpa.clock"] = clock;
    emit(g_state.sched_event_id, ts, args);
    mark = in.timestamp;
    emitted++;
  }
  // A read that held events and emitted none is the failure this diagnostic exists for.
  static int silent = 0;
  if (verbose) {
    std::map<uint32_t, unsigned> per_thread;
    std::map<int, unsigned> per_type;
    uint64_t lo = ~0ull, hi = 0;
    for (uint32_t i = 0; i < got; i++) {
      per_thread[ev[i].dpa_thread_id]++;
      per_type[static_cast<int>(ev[i].type)]++;
      if (ev[i].timestamp < (1ull << 48)) {
        lo = std::min<uint64_t>(lo, ev[i].timestamp);
        hi = std::max<uint64_t>(hi, ev[i].timestamp);
      }
    }
    std::string th, ty;
    for (const auto& [t, n] : per_thread) th += std::to_string(t) + ":" + std::to_string(n) + " ";
    for (const auto& [t, n] : per_type) ty += std::to_string(t) + ":" + std::to_string(n) + " ";
    DC_LOG_INFO(
        "dpa events tick: process %u got=%u emitted=%u sane=[%llu,%llu] threads{%s} "
        "types{%s}",
        proc_id, got, emitted, (unsigned long long)lo, (unsigned long long)hi, th.c_str(),
        ty.c_str());
  }
  if (diag++ < 5 || (got > 1 && emitted == 0 && silent++ < 10)) {
    uint64_t lo = ~0ull, hi = 0;
    for (uint32_t i = 0; i < got; i++) {
      lo = std::min<uint64_t>(lo, ev[i].timestamp);
      hi = std::max<uint64_t>(hi, ev[i].timestamp);
    }
    DC_LOG_INFO("dpa events: cap=%u got=%u emitted=%u stamps=[%llu,%llu] threads=%zu", cap, got,
                emitted, (unsigned long long)lo, (unsigned long long)hi,
                g_state.last_event_us.size());
  }
  // The buffer is not a ring in practice: once its page is full the device records nothing more
  // for the process and every read returns the same page. A stop and start empties it; what the
  // thread does during that gap is lost, a few microseconds per page of 2048 entries.
  if (got >= cap / 2) {
    doca_telemetry_dpa_counter_stop(g_state.dpa, g_state.all_proc,
                                    DOCA_TELEMETRY_DPA_COUNTER_TYPE_EVENT_TRACER);
    if (doca_telemetry_dpa_counter_start(g_state.dpa, g_state.all_proc,
                                         DOCA_TELEMETRY_DPA_COUNTER_TYPE_EVENT_TRACER) !=
        DOCA_SUCCESS)
      g_state.perf_started = false;
    g_state.pages_flipped++;
    if (verbose) DC_LOG_INFO("dpa events: process %u page full, tracer re-armed", proc_id);
  }
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
  // The event buffer is per process and 2048 entries deep, and a DPA thread with one activation
  // per message fills it in 130 ms; the read must flip the page before then, so it has its own
  // interval, DATACRUMBS_DPA_EVENT_MS, 5 ms unless set.
  unsigned int event_ms = 5;
  if (const char* ms = std::getenv("DATACRUMBS_DPA_EVENT_MS"); ms != nullptr && std::atoi(ms) > 0)
    event_ms = static_cast<unsigned int>(std::atoi(ms));
  api->register_sampler(event_ms, sample_events);
  DC_LOG_INFO("dpa telemetry plugin: sampling DPA %s every %u ms, events every %u ms",
              g_state.want_events ? "schedule events" : "thread counters", interval, event_ms);
  return true;
}
