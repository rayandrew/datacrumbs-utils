// SPDX-License-Identifier: MIT

// Turns the DC_DPA records a DPA kernel wrote into trace events, parsed as text at
// fini so parsing does not race the app's own writer.
// Also owns the DPA clock anchor: pairs the DPA clock with the global epoch by RPC-ing
// a device kernel, then fits a line through the samples rather than trusting one reading.

#include <datacrumbs/common/logging.h>
#include <datacrumbs/common/singleton.h>
#include <datacrumbs/datacrumbs_utils_config.h>
#include <datacrumbs/utils/client/dpa/library.h>
#include <datacrumbs/utils/common/background.h>
#include <datacrumbs/utils/common/clock.h>
#include <datacrumbs/utils/common/configuration_manager.h>
#include <datacrumbs/utils/common/constants.h>
#include <datacrumbs/utils/common/dpa_anchor_snapshot.h>
#include <datacrumbs/utils/common/pfw_sink.h>
#include <datacrumbs/utils/timesync/timesync_reader.h>
#include <dlfcn.h>
#include <fcntl.h>
#include <pthread.h>
#include <sys/mman.h>
#include <unistd.h>

#include <atomic>
#include <chrono>
#include <cmath>
#include <condition_variable>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <mutex>
#include <string>
#include <thread>

#if DATACRUMBS_UTILS_HAVE_DPA_ANCHOR
#include <doca_dev.h>
#include <doca_dpa.h>
#include <doca_error.h>
#include <doca_mmap.h>
#include <doca_sync_event.h>
#include <gotcha/gotcha.h>

// The dpacc-built kernel archive lives in libdatacrumbs_dpa_anchor.so, loaded here from the
// anchor thread rather than linked into the client. Linking it directly runs its registration
// constructor on the traced process's main thread, and the API wrappers then log those calls
// as the program's own.
struct doca_dpa_app* g_anchor_app = nullptr;
doca_dpa_func_t* g_rpc_kernel = nullptr;
doca_dpa_func_t* g_window_kernel = nullptr;
#endif  // DATACRUMBS_UTILS_HAVE_DPA_ANCHOR

namespace {
// cat groups by the library surface, type names the instrumentation that produced it.
// Macros, not constants: folded into the format string at compile time, so no record pays a
// strlen and a copy to pass them as %s arguments.
#define DC_CAT "DPA"
#define DC_TYPE "dpa"

/// The module's sink, held by the singleton. A type of its own because Singleton keys on the type
/// and every module has a sink of its own, which must not be shared.
struct DpaSink {
  datacrumbs::client::PfwSink sink{"dpa", DATACRUMBS_ENV_DPA_OUT};
};

/// Borrowed, so no reference counting on a path that runs per parsed record.
inline datacrumbs::client::PfwSink* sink() {
  DpaSink* s = datacrumbs::Singleton<DpaSink>::get();
  return s != nullptr ? &s->sink : nullptr;
}

/// No namespace-scope std::string here: the constructor that calls init() lives in another
/// translation unit, so a non-trivial global in this one is not guaranteed to be constructed yet.
/// The path is read from the manager at both ends instead, which is a function-local static.
const std::string& trace_path() {
  return datacrumbs::ConfigurationManager::runtime().dpa_trace;
}

/// Reads "key=<unsigned>" out of one record. Absent keys leave the default, so a record from an
/// older kernel still produces an event rather than being dropped.
unsigned long field(const char* line, const char* key, unsigned long dflt = 0) {
  char pat[32];
  std::snprintf(pat, sizeof(pat), " %s=", key);
  const char* p = std::strstr(line, pat);
  if (p == nullptr) return dflt;
  return std::strtoul(p + std::strlen(pat), nullptr, 10);
}

/// Where a running fit came from, so a warning or a log line can say which path is in effect
/// instead of leaving it to be inferred from which fields are set.
enum class FitSource { kNone, kManual, kFitted };

/// window is the default: a bounded burst kernel read from the Arm side, under 1 us per anchor.
/// rpc brackets a blocking doca_dpa_rpc, 7 ms per anchor, and is the automatic fallback when the
/// window setup fails. off exists only for an overhead baseline. DATACRUMBS_DPA_ANCHOR_MODE.
enum class AnchorMode { kRpc, kWindow, kOff };

AnchorMode parse_anchor_mode(const std::string& s) {
  if (s == "rpc") return AnchorMode::kRpc;
  if (s == "off") return AnchorMode::kOff;
  if (!s.empty() && s != "window")
    DC_LOG_WARN("[dpa] anchor mode \"%s\" is not window|rpc|off; using window", s.c_str());
  return AnchorMode::kWindow;
}

#if DATACRUMBS_UTILS_HAVE_DPA_ANCHOR
/// One 64B block: DPA window accesses are 64B aligned, so a slot the DPA writes and one the Arm
/// writes must not share a cache line. Mirrors dc_dpa_window_slot in anchor_kernel_dev.c exactly -
/// same field order and width, since dpacc and this compiler must agree on the layout without a
/// shared header between the two toolchains.
struct alignas(64) WindowSlot {
  volatile uint64_t a;
  volatile uint64_t b;
  uint8_t pad[48];
};
static_assert(sizeof(WindowSlot) == 64, "dc_dpa_window_slot must stay one window-aligned block");

/// Mirrors dc_dpa_window_mem in anchor_kernel_dev.c. pulse is the DPA's continuous clock stream.
/// req and resp are the round-trip probe that gives the burst its err_ns. ctrl ends the burst:
/// the kernel holds one execution unit until it sees ctrl.a != 0, so the burst is bounded by how
/// promptly the Arm sets it, not by a guess on the DPA side.
struct WindowMem {
  WindowSlot pulse;
  WindowSlot req;
  WindowSlot resp;
  WindowSlot ctrl;
};

/// Clean-and-invalidate one 64B line and wait for it to land, so the next read refetches rather
/// than reusing a cached copy. Memory the DPA writes through its window never enters the Arm's
/// cache hierarchy. dc civac is the only cache-maintenance instruction available at EL0, and
/// it costs on the order of a few hundred ns.
inline void civac_line(const volatile void* p) {
  asm volatile("dc civac, %0" ::"r"(p) : "memory");
  asm volatile("dsb sy" ::: "memory");
}

/// Clean one 64B line and wait for it to land, after a write. An Arm store lands in the Arm's own
/// cache first, and the DPA reads shared memory through DMA rather than that cache, so without
/// this the DPA can spin forever on a value that never left the Arm.
inline void cvac_line(const volatile void* p) {
  asm volatile("dc cvac, %0" ::"r"(p) : "memory");
  asm volatile("dsb sy" ::: "memory");
}
#endif  // DATACRUMBS_UTILS_HAVE_DPA_ANCHOR

/// Anchor pairing one DPA tick with the global epoch, from DATACRUMBS_DPA_ANCHOR. A single fixed
/// offset with no drift term, good only to whatever the caller measured. It overrides the
/// automated loop: a caller who set this by hand presumably has a reason, such as replaying an
/// earlier trace's own anchor.
struct ManualAnchor {
  bool valid = false;
  unsigned long dpa_us = 0;
  unsigned long long global_ns = 0;
  unsigned long long err_ns = 0;
} g_manual;

void parse_manual_anchor(const std::string& spec) {
  if (spec.empty()) return;
  unsigned long long dpa = 0, global = 0, err = 0;
  const int n = std::sscanf(spec.c_str(), "%llu:%llu:%llu", &dpa, &global, &err);
  if (n < 2) {
    DC_LOG_WARN("[dpa] anchor %s is not <dpa_us>:<global_ns>[:<err_ns>]; staying on the DPA clock",
                spec.c_str());
    return;
  }
  g_manual = {true, static_cast<unsigned long>(dpa), global, err};
}

/// A running least-squares fit of global_ns onto the DPA clock's own ns. Centered on the first
/// anchor: the raw values are ns since chip reset and ns since the Unix epoch, both around
/// 1e15-1e18, and a sum of squares at that scale loses the microsecond precision the fit needs.
struct Regression {
  unsigned n = 0;
  unsigned long long x0_dpa_us = 0;  // first anchor, the regression's origin
  unsigned long long y0_ns = 0;
  double sum_x = 0, sum_y = 0, sum_xx = 0, sum_xy = 0;
};

struct AnchorState {
  std::mutex mu;
  void* dev = nullptr;  // struct doca_dev*, opaque here so this struct needs no #if
  void* ctx = nullptr;  // struct doca_dpa*
  AnchorMode mode = AnchorMode::kRpc;
  // Window mode only, opaque here for the same reason as dev/ctx. window_mem is the host buffer
  // both directions of the burst share. window_mmap registers it for the DPA to reach. A kernel
  // cannot dereference a host address directly, so window_mmap_handle is what the launch passes
  // down for the device side to resolve its own pointer.
  void* window_mem = nullptr;   // WindowMem*, aligned_alloc'd, lives for the anchor's whole life
  void* window_mmap = nullptr;  // struct doca_mmap*
  uint32_t window_mmap_handle = 0;
  void* window_comp_event = nullptr;  // struct doca_sync_event*, DPA publisher / CPU subscriber
  uint64_t window_burst_n = 0;        // comp_event's value after burst n. wait_gt(n-1) awaits it
  Regression reg;
  datacrumbs::timesync::Reader::DpaFit fit;
  // The same anchors against CLOCK_MONOTONIC, for the server's plugin: it emits on that clock and
  // the timesync enricher maps to the epoch, so an epoch fit would be mapped twice.
  Regression reg_mono;
  dc_dpa_anchor_snapshot* snap = nullptr;  // mmap of DC_DPA_ANCHOR_SNAPSHOT_PATH, or null
  bool snap_failed = false;
  FitSource source = FitSource::kNone;
  bool warned_drift = false;
  bool spawned = false;  // the tick is registered and must be removed in fini()
  std::atomic<bool> stop{false};
  bool started = false;  // the context is open. only then does fini() tear it down
};

// On the heap and never destroyed. A static object's destructor runs at exit before this
// library's fini(), while the worker still waits on wake, and pthread_cond_destroy then blocks
// on that waiter forever.
AnchorState& anchor() {
  static AnchorState& s = *new AnchorState;
  return s;
}

/// Emits one dpa_anchor record, so a consumer can read every pairing this run took and refit
/// later rather than trusting only what this process decided in the moment.
void emit_anchor_record(unsigned long dpa_us, unsigned long long global_ns,
                        unsigned long long err_ns) {
  if (sink() == nullptr) return;
  char line[384];
  const int n = std::snprintf(
      line, sizeof(line),
      R"({"name":"dpa_anchor","cat":"dftracer","type":"metadata","ph":4,"args":{"hhash":"%s","dpa_us":%lu,"global_ns":%llu,"err_ns":%llu}})"
      "\n",
      sink()->hhash().c_str(), dpa_us, global_ns, err_ns);
  if (n > 0) sink()->write(line, static_cast<std::size_t>(n));
}

/// Folds one anchor into the running fit and returns it. Offset-only after one anchor, offset
/// plus drift from two on. Even one anchor is placed rather than left on the raw DPA clock, which
/// sits days from everything else in a viewer. Needs the caller to already hold anchor().mu.
datacrumbs::timesync::Reader::DpaFit accumulate(Regression& r, unsigned long long dpa_us,
                                                unsigned long long y_ns) {
  datacrumbs::timesync::Reader::DpaFit fit;
  if (r.n == 0) {
    r.x0_dpa_us = dpa_us;
    r.y0_ns = y_ns;
  }
  const double x = (static_cast<double>(dpa_us) - static_cast<double>(r.x0_dpa_us)) * 1000.0;
  const double y = static_cast<double>(y_ns) - static_cast<double>(r.y0_ns);
  r.sum_x += x;
  r.sum_y += y;
  r.sum_xx += x * x;
  r.sum_xy += x * y;
  r.n++;
  fit.anchor_dpa_us = r.x0_dpa_us;
  fit.to_synced_ns = static_cast<long long>(r.y0_ns) - static_cast<long long>(r.x0_dpa_us) * 1000LL;
  fit.skew_ppb = 0;
  fit.valid = true;
  if (r.n < 2) return fit;

  const double n = static_cast<double>(r.n);
  const double denom = n * r.sum_xx - r.sum_x * r.sum_x;
  if (denom == 0.0) return fit;  // every anchor on the same DPA tick: keep the offset-only fit
  const double slope = (n * r.sum_xy - r.sum_x * r.sum_y) / denom;
  const double intercept = (r.sum_y - slope * r.sum_x) / n;
  fit.to_synced_ns = static_cast<long long>(static_cast<double>(r.y0_ns) + intercept -
                                            static_cast<double>(r.x0_dpa_us) * 1000.0);
  fit.skew_ppb = static_cast<long long>((slope - 1.0) * 1e9);
  return fit;
}

/// Publishes the CLOCK_MONOTONIC fit for the server's dpa_telemetry plugin. Last writer wins when
/// several traced processes anchor at once. The DPA clock is one per device, so any fit applies.
void publish_locked(const datacrumbs::timesync::Reader::DpaFit& m, unsigned n,
                    unsigned long long err_ns) {
  auto& s = anchor().snap;
  if (s == nullptr) {
    if (anchor().snap_failed) return;
    const int fd = ::open(DC_DPA_ANCHOR_SNAPSHOT_PATH, O_RDWR | O_CREAT, 0644);
    void* p = MAP_FAILED;
    if (fd >= 0 && ::ftruncate(fd, sizeof(dc_dpa_anchor_snapshot)) == 0)
      p = ::mmap(nullptr, sizeof(dc_dpa_anchor_snapshot), PROT_READ | PROT_WRITE, MAP_SHARED, fd,
                 0);
    if (fd >= 0) ::close(fd);
    if (p == MAP_FAILED) {
      anchor().snap_failed = true;
      DC_LOG_WARN(
          "[dpa] cannot publish the anchor fit at %s; DPA telemetry events stay on their "
          "sample time",
          DC_DPA_ANCHOR_SNAPSHOT_PATH);
      return;
    }
    s = static_cast<dc_dpa_anchor_snapshot*>(p);
  }
  const uint32_t odd = (__atomic_load_n(&s->seq, __ATOMIC_RELAXED) | 1u);
  __atomic_store_n(&s->seq, odd, __ATOMIC_RELEASE);
  s->magic = DC_DPA_ANCHOR_MAGIC;
  s->n = n;
  s->anchor_dpa_us = m.anchor_dpa_us;
  s->to_mono_ns = m.to_synced_ns;
  s->skew_ppb = m.skew_ppb;
  s->err_ns = err_ns;
  s->written_mono_ns = datacrumbs::client::mono_ns();
  s->valid = 1;
  __atomic_store_n(&s->seq, odd + 1, __ATOMIC_RELEASE);
}

void update_fit_locked(unsigned long long dpa_us, unsigned long long global_ns,
                       unsigned long long mono_ns, unsigned long long err_ns) {
  Regression& r = anchor().reg;
  anchor().fit = accumulate(r, dpa_us, global_ns);
  anchor().source = FitSource::kFitted;
  publish_locked(accumulate(anchor().reg_mono, dpa_us, mono_ns), r.n, err_ns);
  if (r.n < 2) return;

  const double x = (static_cast<double>(dpa_us) - static_cast<double>(r.x0_dpa_us)) * 1000.0;
  const double skew_ppm = static_cast<double>(anchor().fit.skew_ppb) / 1000.0;
  // The DPA clock typically runs 6 to 8 ppm from the host clock. A skew far outside that range
  // is a unit or scale error, not drift. The fit needs at least a minute of span to resolve
  // ppm at all.
  constexpr double kMaxPlausiblePpm = 50.0;
  if (!anchor().warned_drift && r.n >= 10 && x >= 60e9 && std::fabs(skew_ppm) > kMaxPlausiblePpm) {
    DC_LOG_WARN("[dpa] anchor fit skew %.3f ppm is not plausible for a DPA clock (n=%u anchors)",
                skew_ppm, r.n);
    anchor().warned_drift = true;
  }
}

#if DATACRUMBS_UTILS_HAVE_DPA_ANCHOR

/// The first device that offers a DPA context, or the one DATACRUMBS_DPA_DEV names. That is a
/// PCI-address substring, the same convention as DATACRUMBS_HWTS_DOCA_DEV.
struct doca_dev* open_anchor_device() {
  const std::string& want = datacrumbs::ConfigurationManager::runtime().dpa_dev;
  struct doca_devinfo** list = nullptr;
  uint32_t n = 0;
  if (doca_devinfo_create_list(&list, &n) != DOCA_SUCCESS) return nullptr;
  struct doca_dev* dev = nullptr;
  for (uint32_t i = 0; i < n; i++) {
    if (!want.empty()) {
      char addr[DOCA_DEVINFO_PCI_ADDR_SIZE] = {0};
      if (doca_devinfo_get_pci_addr_str(list[i], addr) != DOCA_SUCCESS) continue;
      if (std::strstr(addr, want.c_str()) == nullptr) continue;
    }
    if (doca_dpa_cap_is_supported(list[i]) != DOCA_SUCCESS) continue;
    if (doca_dev_open(list[i], &dev) == DOCA_SUCCESS) break;
    dev = nullptr;
  }
  doca_devinfo_destroy_list(list);
  return dev;
}

bool setup_window_locked(struct doca_dev* dev);  // defined below, start_anchor_locked calls it

/// Opens this module's own doca_dpa context and loads the anchor kernel. Returns false, with the
/// DOCA error logged, on any failure. A second doca_dpa_create on a PF the traced app already
/// holds a context on can time out rather than fail cleanly, so this never retries or falls back.
/// It leaves DPA records on dpa_raw and logs why.
bool start_anchor_locked() {
  struct doca_dev* dev = open_anchor_device();
  if (dev == nullptr) {
    DC_LOG_WARN(
        "[dpa] no device offers a DPA context (DATACRUMBS_DPA_DEV=\"%s\"); DPA records stay on "
        "dpa_raw",
        datacrumbs::ConfigurationManager::runtime().dpa_dev.c_str());
    return false;
  }
  struct doca_dpa* ctx = nullptr;
  doca_error_t result = doca_dpa_create(dev, &ctx);
  if (result != DOCA_SUCCESS) {
    DC_LOG_WARN("[dpa] doca_dpa_create failed: %s; DPA records stay on dpa_raw",
                doca_error_get_descr(result));
    doca_dev_close(dev);
    return false;
  }
  result = doca_dpa_set_app(ctx, g_anchor_app);
  if (result == DOCA_SUCCESS) result = doca_dpa_start(ctx);
  if (result != DOCA_SUCCESS) {
    DC_LOG_WARN("[dpa] starting the anchor's DPA context failed: %s; DPA records stay on dpa_raw",
                doca_error_get_descr(result));
    doca_dpa_destroy(ctx);
    doca_dev_close(dev);
    return false;
  }
  anchor().dev = dev;
  anchor().ctx = ctx;
  if (anchor().mode == AnchorMode::kWindow && !setup_window_locked(dev))
    anchor().mode = AnchorMode::kRpc;
  return true;
}

/// Registers the one buffer every window burst reuses, and resolves the handle the kernel needs
/// to reach it through its own device. A CPU-type mmap, plain host memory, not a DPA one: the Arm
/// side writes req/ctrl and reads pulse/resp with no copy. A kernel cannot dereference an Arm
/// address directly, so doca_mmap_dev_get_dpa_handle is what makes the buffer visible to it.
bool setup_window_locked(struct doca_dev* dev) {
  void* mem = std::aligned_alloc(64, sizeof(WindowMem));
  if (mem == nullptr) return false;
  std::memset(mem, 0, sizeof(WindowMem));

  struct doca_mmap* mmap = nullptr;
  doca_error_t result = doca_mmap_create(&mmap);
  if (result == DOCA_SUCCESS)
    result = doca_mmap_set_permissions(mmap, DOCA_ACCESS_FLAG_LOCAL_READ_WRITE);
  if (result == DOCA_SUCCESS) result = doca_mmap_set_memrange(mmap, mem, sizeof(WindowMem));
  if (result == DOCA_SUCCESS) result = doca_mmap_add_dev(mmap, dev);
  if (result == DOCA_SUCCESS) result = doca_mmap_start(mmap);
  uint32_t handle = 0;
  if (result == DOCA_SUCCESS) result = doca_mmap_dev_get_dpa_handle(mmap, dev, &handle);
  if (result != DOCA_SUCCESS) {
    DC_LOG_WARN("[dpa] window mmap setup failed: %s; anchor mode stays on rpc",
                doca_error_get_descr(result));
    if (mmap != nullptr) doca_mmap_destroy(mmap);
    std::free(mem);
    return false;
  }

  struct doca_sync_event* comp_event = nullptr;
  result = doca_sync_event_create(&comp_event);
  if (result == DOCA_SUCCESS)
    result = doca_sync_event_add_publisher_location_dpa(
        comp_event, static_cast<struct doca_dpa*>(anchor().ctx));
  if (result == DOCA_SUCCESS) result = doca_sync_event_add_subscriber_location_cpu(comp_event, dev);
  if (result == DOCA_SUCCESS) result = doca_sync_event_start(comp_event);
  if (result != DOCA_SUCCESS) {
    DC_LOG_WARN("[dpa] window completion event setup failed: %s; anchor mode stays on rpc",
                doca_error_get_descr(result));
    if (comp_event != nullptr) doca_sync_event_destroy(comp_event);
    doca_mmap_destroy(mmap);
    std::free(mem);
    return false;
  }

  anchor().window_mem = mem;
  anchor().window_mmap = mmap;
  anchor().window_mmap_handle = handle;
  anchor().window_comp_event = comp_event;
  return true;
}

void teardown_window_locked() {
  if (anchor().window_comp_event != nullptr)
    doca_sync_event_destroy(static_cast<struct doca_sync_event*>(anchor().window_comp_event));
  if (anchor().window_mmap != nullptr)
    doca_mmap_destroy(static_cast<struct doca_mmap*>(anchor().window_mmap));
  if (anchor().window_mem != nullptr) std::free(anchor().window_mem);
  anchor().window_comp_event = nullptr;
  anchor().window_mmap = nullptr;
  anchor().window_mem = nullptr;
}

void stop_anchor_locked() {
  if (anchor().mode == AnchorMode::kWindow) teardown_window_locked();
  if (anchor().ctx != nullptr) doca_dpa_destroy(static_cast<struct doca_dpa*>(anchor().ctx));
  if (anchor().dev != nullptr) doca_dev_close(static_cast<struct doca_dev*>(anchor().dev));
  anchor().ctx = nullptr;
  anchor().dev = nullptr;
}

/// One anchor: bracket a blocking doca_dpa_rpc call with two host reads, take the midpoint as the
/// host time and half the width as its error.
bool take_anchor_locked() {
  if (anchor().ctx == nullptr) return false;
  // doca_dpa_rpc takes uint64_t*, not unsigned long long*: same width on aarch64 but a distinct
  // type, so the wrong one fails to compile rather than silently truncating.
  uint64_t retval = 0;
  const unsigned long long t0 = datacrumbs::client::mono_ns();
  const doca_error_t rc =
      doca_dpa_rpc(static_cast<struct doca_dpa*>(anchor().ctx), g_rpc_kernel, &retval);
  const unsigned long long t1 = datacrumbs::client::mono_ns();
  if (rc != DOCA_SUCCESS) {
    DC_LOG_WARN("[dpa] anchor doca_dpa_rpc failed: %s", doca_error_get_descr(rc));
    return false;
  }

  const unsigned long long mid = t0 + (t1 - t0) / 2;
  const unsigned long long err_ns = (t1 - t0) / 2;
  const unsigned long long global_ns = sink() != nullptr ? sink()->clock().remap(mid) : mid;

  update_fit_locked(retval, global_ns, mid, err_ns);
  emit_anchor_record(static_cast<unsigned long>(retval), global_ns, err_ns);
  return true;
}

/// One window-mode anchor: launch the bounded burst kernel, poll its pulse slot with cache
/// maintenance to confirm it is running and count pairs, fire one round-trip echo partway
/// through, then end the burst and take that round trip as the anchor. Same shape as
/// take_anchor_locked's RPC bracket, just far tighter since it brackets a poll, not a blocking RPC.
bool take_window_anchor_locked() {
  if (anchor().ctx == nullptr || anchor().window_mem == nullptr) return false;
  auto* m = static_cast<WindowMem*>(anchor().window_mem);
  std::memset(const_cast<void*>(static_cast<volatile void*>(m)), 0, sizeof(*m));
  cvac_line(&m->req);
  cvac_line(&m->ctrl);

  const unsigned burst_us = datacrumbs::ConfigurationManager::runtime().dpa_anchor_burst_us;
  const uint64_t burst_n = ++anchor().window_burst_n;
  // The launch sets the completion event to comp_count, so the count must grow with the burst
  // number or the wait below is satisfied only once.
  doca_error_t rc = doca_dpa_kernel_launch_update_set(
      static_cast<struct doca_dpa*>(anchor().ctx), nullptr, 0,
      static_cast<struct doca_sync_event*>(anchor().window_comp_event), burst_n, 1, g_window_kernel,
      static_cast<uint64_t>(anchor().window_mmap_handle), reinterpret_cast<uint64_t>(m),
      static_cast<uint64_t>(burst_us));
  if (rc != DOCA_SUCCESS) {
    DC_LOG_WARN("[dpa] window kernel launch failed: %s", doca_error_get_descr(rc));
    return false;
  }

  const auto deadline = std::chrono::steady_clock::now() + std::chrono::microseconds(burst_us);
  uint64_t last_seq = 0, req_seq = 1;
  unsigned long long resp_t0 = 0, resp_t1 = 0, resp_dpa_us = 0;
  unsigned long long first_dpa_us = 0, last_dpa_us = 0;
  bool req_sent = false, got_resp = false;
  unsigned pairs = 0;

  while (std::chrono::steady_clock::now() < deadline) {
    civac_line(&m->pulse);
    const uint64_t seq = m->pulse.a;
    if (seq != 0 && seq != last_seq) {
      last_seq = seq;
      last_dpa_us = m->pulse.b;
      if (first_dpa_us == 0) first_dpa_us = last_dpa_us;
      pairs++;
      // Fire the round trip once the burst is clearly running, not on the very first sample:
      // an early write can land before the kernel has looped back around to check req.
      if (!req_sent && pairs >= 2) {
        resp_t0 = datacrumbs::client::mono_ns();
        m->req.a = req_seq;
        cvac_line(&m->req);
        req_sent = true;
      }
    }
    if (req_sent && !got_resp) {
      civac_line(&m->resp);
      if (m->resp.a == req_seq) {
        resp_t1 = datacrumbs::client::mono_ns();
        resp_dpa_us = m->resp.b;
        got_resp = true;
      }
    }
  }
  m->ctrl.a = 1;  // release the execution unit. no burst is held past its own deadline
  cvac_line(&m->ctrl);

  // Bounded poll, not doca_sync_event_wait_gt: that call has no timeout, so a kernel that never
  // ends would hang the anchor thread for the life of the process.
  const auto comp_deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(50);
  uint64_t comp = 0;
  for (;;) {
    rc = doca_sync_event_get(static_cast<struct doca_sync_event*>(anchor().window_comp_event),
                             &comp);
    if (rc != DOCA_SUCCESS || comp >= burst_n) break;
    if (std::chrono::steady_clock::now() > comp_deadline) {
      DC_LOG_WARN(
          "[dpa] window burst %llu: kernel did not complete in 50 ms (event=%llu, %u pulses)",
          static_cast<unsigned long long>(burst_n), static_cast<unsigned long long>(comp), pairs);
      return false;
    }
  }
  if (rc != DOCA_SUCCESS) {
    DC_LOG_WARN("[dpa] window completion event read failed: %s", doca_error_get_descr(rc));
    return false;
  }
  if (!got_resp) {
    DC_LOG_WARN("[dpa] window burst saw %u pulse(s) but no round-trip echo; skipping this anchor",
                pairs);
    return false;
  }

  const unsigned long long mid = resp_t0 + (resp_t1 - resp_t0) / 2;
  const unsigned long long err_ns = (resp_t1 - resp_t0) / 2;
  const unsigned long long global_ns = sink() != nullptr ? sink()->clock().remap(mid) : mid;
  update_fit_locked(resp_dpa_us, global_ns, mid, err_ns);
  emit_anchor_record(static_cast<unsigned long>(resp_dpa_us), global_ns, err_ns);
  DC_LOG_INFO("[dpa] window anchor: %u pair(s), err_ns=%llu, burst EU time=%llu us", pairs, err_ns,
              last_dpa_us - first_dpa_us);
  return true;
}

/// Runs on the worker thread, not in init(). dc_dpa_anchor is populated by a dpacc-generated
/// constructor that runs on the same thread before main, in an order unspecified relative to
/// init()'s own, so waiting inside init() could hang forever. Calling doca_dpa_set_app before
/// that constructor runs returns a permanent DOCA_ERROR_INVALID_VALUE.
bool take_anchor_dispatch_locked() {
  return anchor().mode == AnchorMode::kWindow ? take_window_anchor_locked() : take_anchor_locked();
}

/// Loads libdatacrumbs_dpa_anchor.so from the directory this library lives in. Its constructor
/// registers the kernels with DOCA; it runs on the calling thread, under the tracer mark.
bool load_anchor_library() {
  Dl_info info{};
  if (dladdr(reinterpret_cast<void*>(&load_anchor_library), &info) == 0 ||
      info.dli_fname == nullptr) {
    DC_LOG_WARN("[dpa] cannot locate the client library; DPA records stay on dpa_raw");
    return false;
  }
  std::string path(info.dli_fname);
  const auto slash = path.rfind('/');
  path = (slash == std::string::npos ? std::string() : path.substr(0, slash + 1)) +
         "libdatacrumbs_dpa_anchor.so";
  void* h = dlopen(path.c_str(), RTLD_NOW | RTLD_LOCAL);
  if (h == nullptr) {
    DC_LOG_WARN("[dpa] %s; DPA records stay on dpa_raw", dlerror());
    return false;
  }
  auto** app = static_cast<struct doca_dpa_app**>(dlsym(h, "dc_dpa_anchor"));
  g_rpc_kernel = reinterpret_cast<doca_dpa_func_t*>(dlsym(h, "dc_dpa_anchor_kernel"));
  g_window_kernel = reinterpret_cast<doca_dpa_func_t*>(dlsym(h, "dc_dpa_window_kernel"));
  if (app == nullptr || *app == nullptr || g_rpc_kernel == nullptr || g_window_kernel == nullptr) {
    DC_LOG_WARN("[dpa] %s lacks the anchor kernels; DPA records stay on dpa_raw", path.c_str());
    return false;
  }
  g_anchor_app = *app;
  return true;
}

/// One-time bootstrap on the anchor thread: read the mode, load the kernels, open the context and
/// take the first reading. Kept apart from anchor_loop so the loop is only a tick.
bool dpa_anchor_start() {
  anchor().mode = parse_anchor_mode(datacrumbs::ConfigurationManager::runtime().dpa_anchor_mode);
  if (anchor().mode == AnchorMode::kOff) return false;
  if (anchor().stop || !load_anchor_library()) return false;
  std::lock_guard<std::mutex> lk(anchor().mu);
  if (anchor().stop || !start_anchor_locked()) return false;
  anchor().started = true;
  datacrumbs::Singleton<DpaSink>::get_instance();  // anchors need a sink even with no DC_DPA log
  take_anchor_dispatch_locked();
  return true;
}

/// The tick: one anchor reading, on whatever mode the bootstrap settled on. The whole reason this
/// is its own function is so the periodic-task worker can call it directly once it exists.
void take_anchor_tick() {
  std::lock_guard<std::mutex> lk(anchor().mu);
  take_anchor_dispatch_locked();
}

/// The anchor's tick on the client's write worker: the bootstrap on the first call, one reading per
/// interval after. The write worker tolerates the millisecond a burst or the half second a context
/// open takes; the scan worker would lose a lap of completions to either.
std::shared_ptr<datacrumbs::client::Background::Task> g_anchor_task;

bool anchor_tick() {
  static bool booted = false;
  static bool alive = false;
  static unsigned long long next_due_ns = 0;
  if (anchor().stop.load()) return false;
  const unsigned long long now = datacrumbs::client::mono_ns();
  if (!booted) {
    booted = true;
    alive = dpa_anchor_start();
    next_due_ns = now + static_cast<unsigned long long>(
                            datacrumbs::ConfigurationManager::runtime().dpa_anchor_interval_s) *
                            1000000000ull;
    return true;
  }
  if (!alive || now < next_due_ns) return false;
  take_anchor_tick();
  next_due_ns += static_cast<unsigned long long>(
                     datacrumbs::ConfigurationManager::runtime().dpa_anchor_interval_s) *
                 1000000000ull;
  return true;
}

/// Stops the anchor thread and destroys its context. Idempotent. Runs from fini() and from the
/// hook below. The two doca_dpa contexts in one process share state: if the traced program
/// destroys its own context first, a later launch on this one faults inside libdoca_dpa. This
/// context must be destroyed first.
void stop_anchor_now() {
  static std::once_flag once;
  std::call_once(once, [] {
    if (!anchor().spawned) return;
    anchor().stop = true;
    datacrumbs::client::Background::get().remove(g_anchor_task);  // waits out a tick in progress
    if (!anchor().started) return;
    datacrumbs::client::TracerThread tracer;
    std::lock_guard<std::mutex> lk(anchor().mu);
    stop_anchor_locked();
  });
}

gotcha_wrappee_handle_t g_dpa_destroy_handle = nullptr;

doca_error_t dpa_destroy_wrap(struct doca_dpa* dpa) {
  auto real = reinterpret_cast<doca_error_t (*)(struct doca_dpa*)>(
      gotcha_get_wrappee(g_dpa_destroy_handle));
  // Our own teardown comes through here too, on the tracer thread. It must not stop itself.
  if (!datacrumbs::client::tracer_thread_active() && dpa != anchor().ctx) stop_anchor_now();
  return real(dpa);
}

/// A thread created by one of our threads is ours: libdoca starts service threads for the anchor's
/// context from the anchor thread, and without this they record like the program's own.
gotcha_wrappee_handle_t g_pthread_create_handle = nullptr;

struct ThreadStart {
  void* (*fn)(void*);
  void* arg;
};

void* tracer_thread_start(void* p) {
  datacrumbs::client::TracerThread tracer;
  auto* s = static_cast<ThreadStart*>(p);
  void* (*fn)(void*) = s->fn;
  void* arg = s->arg;
  delete s;
  return fn(arg);
}

int pthread_create_wrap(pthread_t* t, const pthread_attr_t* attr, void* (*fn)(void*), void* arg) {
  auto real = reinterpret_cast<int (*)(pthread_t*, const pthread_attr_t*, void* (*)(void*), void*)>(
      gotcha_get_wrappee(g_pthread_create_handle));
  if (!datacrumbs::client::tracer_thread_active()) return real(t, attr, fn, arg);
  return real(t, attr, tracer_thread_start, new ThreadStart{fn, arg});
}

gotcha_binding_t g_dpa_bindings[] = {
    {"doca_dpa_destroy", reinterpret_cast<void*>(dpa_destroy_wrap), &g_dpa_destroy_handle},
    {"pthread_create", reinterpret_cast<void*>(pthread_create_wrap), &g_pthread_create_handle},
};

void install_destroy_hook() {
  const gotcha_error_t rc = gotcha_wrap(g_dpa_bindings, 2, "datacrumbs-dpa");
  if (rc != GOTCHA_SUCCESS && rc != GOTCHA_FUNCTION_NOT_FOUND)
    DC_LOG_WARN("[dpa] gotcha_wrap(doca_dpa_destroy, pthread_create) failed: %d",
                static_cast<int>(rc));
}

#endif  // DATACRUMBS_UTILS_HAVE_DPA_ANCHOR

}  // namespace

void datacrumbs::client::dpa::init() {
  parse_manual_anchor(datacrumbs::ConfigurationManager::runtime().dpa_anchor);
  if (g_manual.valid) {
    anchor().source = FitSource::kManual;
  } else {
#if DATACRUMBS_UTILS_HAVE_DPA_ANCHOR
    // Every DOCA-facing step runs in anchor_tick on the write worker, not here: this is a library
    // constructor, and the dpacc registration in the anchor library must not run on it.
    g_anchor_task = datacrumbs::client::Background::get().add_write(anchor_tick);
    anchor().spawned = true;
    install_destroy_hook();
#endif
  }
  if (trace_path().empty()) return;
  datacrumbs::Singleton<DpaSink>::get_instance();
}

void datacrumbs::client::dpa::fini() {
#if DATACRUMBS_UTILS_HAVE_DPA_ANCHOR
  // No closing anchor: the traced program may have destroyed its DPA context inside main(), and
  // the hook on doca_dpa_destroy has then already stopped ours. The periodic anchors land within
  // one interval of exit.
  stop_anchor_now();
#endif
  if (g_manual.valid) emit_anchor_record(g_manual.dpa_us, g_manual.global_ns, g_manual.err_ns);

  if (sink() == nullptr) return;
  std::FILE* f = std::fopen(trace_path().c_str(), "r");
  if (f == nullptr) {
    if (!trace_path().empty()) DC_LOG_WARN("[dpa] no records at %s", trace_path().c_str());
  } else {
    char line[1024];
    unsigned long seen = 0;
    while (std::fgets(line, sizeof(line), f) != nullptr) {
      const char* rec = std::strstr(line, "DCDPA ");
      if (rec == nullptr) continue;
      const unsigned long t = field(rec, "t");
      // The device log prefixes each line with "/ <eu>/". The EU is what an anchor is valid for.
      char eu[8] = "?";
      if (const char* slash = std::strchr(line, '/')) {
        unsigned int n_eu = 0;
        if (std::sscanf(slash + 1, " %u/", &n_eu) == 1) std::snprintf(eu, sizeof(eu), "%u", n_eu);
      }
      unsigned long long ts_us = t;
      const char* domain = "dpa_raw";
      switch (anchor().source) {
        case FitSource::kManual:
          // A fixed offset, so ts differences equal raw tick differences regardless.
          ts_us = g_manual.global_ns / DATACRUMBS_TIME_DIVISOR_NS +
                  (t - g_manual.dpa_us) * (1000 / DATACRUMBS_TIME_DIVISOR_NS);
          domain = "global";
          break;
        case FitSource::kFitted: {
          const unsigned long long g_ns = sink()->clock().remap_dpa(t, anchor().fit);
          if (g_ns != 0) {
            ts_us = g_ns / DATACRUMBS_TIME_DIVISOR_NS;
            domain = "global";
          }
          break;
        }
        case FitSource::kNone:
          break;
      }
      auto emit = [&](const char* kind, unsigned long a, unsigned long b, unsigned long c,
                      unsigned long d, unsigned long e) {
        char out[640];
        const int on = std::snprintf(
            out, sizeof(out),
            R"({"id":%llu,"name":"dpa.%s","cat":")" DC_CAT R"(","type":")" DC_TYPE
            R"(","pid":0,"tid":0,"ts":%llu,"dur":0,"ph":2,"args":{"hhash":"%s","dpa.clock":"%s","dpa.eu":"%s","dpa.us":%lu,"wr":%lu,"imm":%lu,"val":%lu,"type":%lu,"ud":%lu}})"
            "\n",
            static_cast<unsigned long long>(sink()->next_id()), kind, ts_us,
            sink()->hhash().c_str(), domain, eu, t, a, b, c, d, e);
        if (on > 0) sink()->write(out, static_cast<std::size_t>(on));
      };
      // A record whose fields are its own, not the join keys of a received completion.
      auto emit_handler = [&](unsigned long cycles, unsigned long messages) {
        char out[640];
        const int on = std::snprintf(
            out, sizeof(out),
            R"({"id":%llu,"name":"dpa.handler","cat":")" DC_CAT R"(","type":")" DC_TYPE
            R"(","pid":0,"tid":0,"ts":%llu,"dur":0,"ph":2,"args":{"hhash":"%s","dpa.clock":"%s")"
            R"(,"dpa.eu":"%s","dpa.us":%lu,"dpa.handler_cycles":%lu,"dpa.handler_msgs":%lu}})"
            "\n",
            static_cast<unsigned long long>(sink()->next_id()), ts_us, sink()->hhash().c_str(),
            domain, eu, t, cycles, messages);
        if (on > 0) sink()->write(out, static_cast<std::size_t>(on));
      };
      if (std::strstr(rec, "DCDPA rx") != nullptr)
        emit("rx", field(rec, "wr"), field(rec, "imm"), field(rec, "val"), field(rec, "type"),
             field(rec, "ud"));
      else if (std::strstr(rec, "DCDPA tx") != nullptr)
        emit("tx", field(rec, "a"), field(rec, "b"), field(rec, "sent"), 0, 0);
      // The handler's own cost: the cycles and the messages they cover, so the wake path is what
      // an activation costs on top of this.
      else if (std::strstr(rec, "DCDPA hnd") != nullptr)
        emit_handler(field(rec, "cyc"), field(rec, "msg"));
      else
        continue;
      ++seen;
    }
    std::fclose(f);
    DC_LOG_INFO("[dpa] %lu record(s) from %s", seen, trace_path().c_str());
  }
  datacrumbs::Singleton<DpaSink>::finalize();  // destroys the sink, which flushes and closes
}
