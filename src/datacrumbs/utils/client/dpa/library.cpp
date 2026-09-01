// SPDX-License-Identifier: MIT

// Turns the DC_DPA records a DPA kernel wrote into trace events.
//
// The records arrive as text because the device log is the only path out of a DPA thread handler
// (dc_dpa_trace.h says why), so this parses rather than reads a binary buffer. Parsing happens at
// fini rather than while the workload runs: the file is the app's own log, and reading it as it is
// written would race the writer for no benefit.

#include <datacrumbs/common/logging.h>
#include <datacrumbs/common/singleton.h>
#include <datacrumbs/utils/client/dpa/library.h>
#include <datacrumbs/utils/common/configuration_manager.h>
#include <datacrumbs/utils/common/constants.h>
#include <datacrumbs/utils/common/pfw_sink.h>

#include <cstdio>
#include <cstring>
#include <string>

namespace {
// The labels this module puts on every record it writes: cat groups by the library surface,
// type names the instrumentation that produced it. Declared here rather than centrally so a
// module owns its own, as dftracer does in brahma/posix.cpp.
// Macros, not constants: folded into the format string at compile time they cost nothing,
// where passing them as %s arguments costs a strlen and a copy on every record.
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

/// Anchor pairing one DPA tick with the global epoch, from DATACRUMBS_DPA_ANCHOR. Unset leaves
/// records on the DPA clock: guessing an offset would put them on the shared axis while being wrong
/// by an unknown amount, which is the failure this whole timeline work exists to remove.
struct Anchor {
  bool valid = false;
  unsigned long dpa_us = 0;
  unsigned long long global_ns = 0;
  unsigned long long err_ns = 0;
} g_anchor;

void parse_anchor(const std::string& spec) {
  if (spec.empty()) return;
  unsigned long long dpa = 0, global = 0, err = 0;
  const int n = std::sscanf(spec.c_str(), "%llu:%llu:%llu", &dpa, &global, &err);
  if (n < 2) {
    DC_LOG_WARN("[dpa] anchor %s is not <dpa_us>:<global_ns>[:<err_ns>]; staying on the DPA clock",
                spec.c_str());
    return;
  }
  g_anchor = {true, static_cast<unsigned long>(dpa), global, err};
}

/// The DPA clock counts microseconds from an arbitrary start point, per execution unit. Two EUs on
/// this chip share that origin to within a tick as measured, but the intrinsic does not promise it,
/// so the EU is recorded per event.
///
/// The anchor is a constant offset, so ts differences equal raw tick differences: DPA to DPA timing
/// is exact whether or not one is applied, and the raw tick is not carried. What the anchor cannot
/// give is absolute accuracy - dpa.anchor_err_ns states that, and it is milliseconds, so these
/// timestamps place a record on the shared axis but must not join a microsecond event to an ARM
/// one. The anchor itself is emitted once as metadata, which is what re-anchoring needs.
void emit(const char* kind, const char* eu, unsigned long t, unsigned long a, unsigned long b,
          unsigned long c, unsigned long d, unsigned long e) {
  if (sink() == nullptr) return;
  unsigned long long ts_us = t;
  const char* domain = "dpa_raw";
  if (g_anchor.valid) {
    // The anchor is nanoseconds and the device clock is microseconds, so each is scaled to
    // the trace's unit separately rather than added and converted once.
    ts_us = g_anchor.global_ns / DATACRUMBS_TIME_DIVISOR_NS +
            (t - g_anchor.dpa_us) * (1000 / DATACRUMBS_TIME_DIVISOR_NS);
    domain = "global";
  }
  char line[640];
  const int n = std::snprintf(
      line, sizeof(line),
      R"({"id":%llu,"name":"dpa.%s","cat":")" DC_CAT R"(","type":")" DC_TYPE
      R"(","pid":0,"tid":0,"ts":%llu,"dur":0,"ph":2,"args":{"hhash":"%s","dpa.clock":"%s","dpa.eu":"%s","wr":%lu,"imm":%lu,"val":%lu,"type":%lu,"ud":%lu}})"
      "\n",
      static_cast<unsigned long long>(sink()->next_id()), kind, ts_us, sink()->hhash().c_str(),
      domain, eu, a, b, c, d, e);
  if (n > 0) sink()->write(line, static_cast<std::size_t>(n));
}

}  // namespace

void datacrumbs::client::dpa::init() {
  if (trace_path().empty()) return;
  parse_anchor(datacrumbs::ConfigurationManager::runtime().dpa_anchor);
  datacrumbs::Singleton<DpaSink>::get_instance();
}

/// The pairing this run used, so a consumer can undo it and apply a better one. Without this the
/// anchor lives only in the environment and a trace cannot be re-anchored.
void emit_anchor_metadata() {
  if (sink() == nullptr || !g_anchor.valid) return;
  char line[384];
  const int n = std::snprintf(
      line, sizeof(line),
      R"({"name":"dpa_anchor","cat":"dftracer","type":"metadata","pid":0,"tid":0,"ph":4,"args":{"hhash":"%s","dpa_us":%lu,"global_ns":%llu,"err_ns":%llu}})"
      "\n",
      sink()->hhash().c_str(), g_anchor.dpa_us, g_anchor.global_ns, g_anchor.err_ns);
  if (n > 0) sink()->write(line, static_cast<std::size_t>(n));
}

void datacrumbs::client::dpa::fini() {
  if (sink() == nullptr) return;
  emit_anchor_metadata();
  std::FILE* f = std::fopen(trace_path().c_str(), "r");
  if (f == nullptr) {
    DC_LOG_WARN("[dpa] no records at %s", trace_path().c_str());
  } else {
    char line[1024];
    unsigned long seen = 0;
    while (std::fgets(line, sizeof(line), f) != nullptr) {
      const char* rec = std::strstr(line, "DCDPA ");
      if (rec == nullptr) continue;
      const unsigned long t = field(rec, "t");
      // The device log prefixes each line with "/ <eu>/"; the EU is what an anchor is valid for.
      char eu[8] = "?";
      if (const char* slash = std::strchr(line, '/')) {
        unsigned int n_eu = 0;
        if (std::sscanf(slash + 1, " %u/", &n_eu) == 1) std::snprintf(eu, sizeof(eu), "%u", n_eu);
      }
      if (std::strstr(rec, "DCDPA rx") != nullptr)
        emit("rx", eu, t, field(rec, "wr"), field(rec, "imm"), field(rec, "val"),
             field(rec, "type"), field(rec, "ud"));
      else if (std::strstr(rec, "DCDPA tx") != nullptr)
        emit("tx", eu, t, field(rec, "a"), field(rec, "b"), field(rec, "sent"), 0, 0);
      else
        continue;
      ++seen;
    }
    std::fclose(f);
    DC_LOG_INFO("[dpa] %lu record(s) from %s", seen, trace_path().c_str());
  }
  datacrumbs::Singleton<DpaSink>::finalize();  // destroys the sink, which flushes and closes
}
