// Plugin: attach hardware perf counters (DATACRUMBS_HW_COUNTERS, cpu-scope) and name the per-event
// entry->exit deltas the core BPF captures. Core owns the capture-time read (it must run in-kernel
// on the event's cpu); this plugin owns the policy: which counters, opening them, and labeling. IPC
// is left to analysis (store raw instructions + cycles). Loaded via DATACRUMBS_PLUGINS.

#include <datacrumbs/common/constants.h>
#include <datacrumbs/common/data_structures.h>
#include <datacrumbs/common/logging.h>
#include <datacrumbs/common/plugin_api.h>
#include <datacrumbs/utils/common/configuration_manager.h>
#include <linux/bpf.h>
#include <linux/perf_event.h>
#include <sys/syscall.h>
#include <unistd.h>

#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>

namespace {

std::vector<std::string> g_counter_names;

struct CounterKind {
  const char* name;
  uint32_t type;
  uint64_t config;
};

const CounterKind kKinds[] = {
    {"instructions", PERF_TYPE_HARDWARE, PERF_COUNT_HW_INSTRUCTIONS},
    {"cycles", PERF_TYPE_HARDWARE, PERF_COUNT_HW_CPU_CYCLES},
    {"cache-misses", PERF_TYPE_HARDWARE, PERF_COUNT_HW_CACHE_MISSES},
    {"cache-references", PERF_TYPE_HARDWARE, PERF_COUNT_HW_CACHE_REFERENCES},
    {"branch-misses", PERF_TYPE_HARDWARE, PERF_COUNT_HW_BRANCH_MISSES},
    {"branches", PERF_TYPE_HARDWARE, PERF_COUNT_HW_BRANCH_INSTRUCTIONS},
    {"page-faults", PERF_TYPE_SOFTWARE, PERF_COUNT_SW_PAGE_FAULTS},
};

const CounterKind* lookup_kind(const std::string& name) {
  for (const auto& k : kKinds)
    if (name == k.name) return &k;
  return nullptr;
}

std::vector<std::string> parse_counter_list() {
  const std::string& counters = datacrumbs::ConfigurationManager::runtime().hw_counters;
  const char* env = counters.c_str();
  std::vector<std::string> names;
  if (env == nullptr || *env == '\0') return names;
  std::string spec(env);
  for (std::size_t start = 0; start <= spec.size() && names.size() < DATACRUMBS_MAX_PMU;) {
    std::size_t sep = spec.find(',', start);
    if (sep == std::string::npos) sep = spec.size();
    std::string name = spec.substr(start, sep - start);
    start = sep + 1;
    if (!name.empty()) names.push_back(name);
  }
  return names;
}

int perf_open(const CounterKind* kind, int cpu) {
  struct perf_event_attr attr = {};
  attr.size = sizeof(attr);
  attr.type = kind->type;
  attr.config = kind->config;
  attr.exclude_hv = 1;
  return static_cast<int>(syscall(__NR_perf_event_open, &attr, -1, cpu, -1, 0UL));
}

int bpf_array_set(int map_fd, uint32_t key, const void* value) {
  union bpf_attr attr = {};
  attr.map_fd = static_cast<uint32_t>(map_fd);
  attr.key = reinterpret_cast<uint64_t>(&key);
  attr.value = reinterpret_cast<uint64_t>(value);
  attr.flags = 0;  // BPF_ANY
  return static_cast<int>(syscall(__NR_bpf, BPF_MAP_UPDATE_ELEM, &attr, sizeof(attr)));
}

// Open a counter cpu-wide on every cpu and store each fd at pmu_counterN[cpu]. Returns false (and
// closes what it opened) if any cpu fails, so a partially-attached counter never reports garbage.
bool attach_counter(const datacrumbs::PluginBpfContext& ctx, int index, const CounterKind* kind,
                    int ncpu) {
  const std::string map_name = "pmu_counter" + std::to_string(index);
  const int map_fd = ctx.get_map_fd(map_name.c_str());
  if (map_fd < 0) {
    DC_LOG_WARN("pmu plugin: core map %s missing", map_name.c_str());
    return false;
  }
  std::vector<int> fds;
  fds.reserve(ncpu);
  for (int cpu = 0; cpu < ncpu; ++cpu) {
    const int fd = perf_open(kind, cpu);
    if (fd < 0) {
      DC_LOG_WARN("pmu plugin: perf_event_open(%s, cpu=%d) failed", kind->name, cpu);
      for (int f : fds) close(f);
      return false;
    }
    if (bpf_array_set(map_fd, static_cast<uint32_t>(cpu), &fd) != 0) {
      close(fd);
      for (int f : fds) close(f);
      return false;
    }
    fds.push_back(fd);  // fds stay open for the process lifetime (the array holds references)
  }
  return true;
}

}  // namespace

extern "C" bool datacrumbs_plugin_register(const datacrumbs::PluginApi* api) {
  if (api == nullptr || api->abi_version != datacrumbs::PluginApi::kAbiVersion) return false;
  g_counter_names = parse_counter_list();
  if (g_counter_names.empty()) {
    DC_LOG_WARN("pmu plugin: DATACRUMBS_HW_COUNTERS unset/empty; no counters attached");
    return true;
  }

  api->register_bpf_ready([](const datacrumbs::PluginBpfContext& ctx) {
    const int ncpu = static_cast<int>(sysconf(_SC_NPROCESSORS_ONLN));
    uint32_t active = 0;
    for (std::size_t i = 0; i < g_counter_names.size(); ++i) {
      const CounterKind* kind = lookup_kind(g_counter_names[i]);
      if (kind == nullptr) {
        DC_LOG_WARN("pmu plugin: unknown counter '%s'", g_counter_names[i].c_str());
        break;  // counters are positional; a gap would mislabel later ones
      }
      if (!attach_counter(ctx, static_cast<int>(active), kind, ncpu)) break;
      ++active;
    }
    g_counter_names.resize(active);
    const int ctl_fd = ctx.get_map_fd("pmu_ctl");
    if (ctl_fd < 0 || bpf_array_set(ctl_fd, 0, &active) != 0) {
      DC_LOG_WARN("pmu plugin: could not set pmu_ctl; counters will stay off");
      return;
    }
    DC_LOG_INFO("pmu plugin: %u counter(s) active over %d cpus", active, ncpu);
  });

  api->register_event_enricher([](datacrumbs::EventWithId* e) {
    if (e->pmu_count == 0) return;
    if (e->args == nullptr) e->args = new DataCrumbsArgs();
    const unsigned int n =
        e->pmu_count < g_counter_names.size() ? e->pmu_count : g_counter_names.size();
    for (unsigned int i = 0; i < n; ++i) {
      (*e->args)[g_counter_names[i]] = static_cast<unsigned long long>(e->pmu[i]);
    }
  });
  return true;
}
