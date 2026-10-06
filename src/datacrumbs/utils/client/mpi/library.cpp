// SPDX-License-Identifier: MIT

// The public MPI and MPI-IO surface, wrapped with GOTCHA. Built without mpi.h: every handle is
// one register or one stack slot wide in both the Open MPI ABI (pointers) and the MPICH ABI
// (ints), so a pointer-wide parameter forwards either unchanged. Sizes come from PMPI_Type_size
// and PMPI_Comm_size, resolved at run time, never wrapped.
//
// Only calls that cross a GOT are seen: the app's and other libraries' (HDF5's). Calls an MPI
// implementation makes inside itself are not, so a collective's internal exchange stays inside
// its record.

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <datacrumbs/common/logging.h>
#include <datacrumbs/common/pfw_format.h>
#include <datacrumbs/common/singleton.h>
#include <datacrumbs/utils/client/mpi/library.h>
#include <datacrumbs/utils/client/wrap/gotcha_wrap.h>
#include <datacrumbs/utils/common/configuration_manager.h>
#include <datacrumbs/utils/common/constants.h>
#include <datacrumbs/utils/common/pfw_sink.h>
#include <datacrumbs/utils/common/tracer_thread.h>
#include <dlfcn.h>
#include <gotcha/gotcha.h>

#include <cstdint>
#include <cstdio>
#include <cstring>
#include <mutex>
#include <unordered_map>

namespace {

#define DC_TYPE "mpi"

using datacrumbs::ConfigurationManager;
using datacrumbs::client::NumArg;
using datacrumbs::client::NumKind;
using CapMode = ConfigurationManager::CaptureMode;
using Hd = void*;

struct MpiSink {
  datacrumbs::client::PfwSink sink{"mpi", DATACRUMBS_ENV_MPI_OUT};
};

inline datacrumbs::client::PfwSink* sink() {
  MpiSink* s = datacrumbs::Singleton<MpiSink>::get();
  return s != nullptr ? &s->sink : nullptr;
}

bool g_torn_down = false;
int g_rank = -1;
thread_local int g_in_mpi = 0;

/// One level only: a wrapped call that reaches another wrapped call through a library forwards it.
struct Reentry {
  bool entered;
  Reentry() : entered(g_in_mpi == 0 && !datacrumbs::client::tracer_thread_active()) {
    if (entered) g_in_mpi = 1;
  }
  ~Reentry() {
    if (entered) g_in_mpi = 0;
  }
};

enum class Cls { FILE, COLL, P2P, WAIT, POLL, ENV };

const char* cat_of(Cls c) {
  switch (c) {
    case Cls::FILE:
      return "MPIIO";
    case Cls::COLL:
      return "MPI_COLL";
    case Cls::P2P:
      return "MPI_P2P";
    case Cls::WAIT:
      return "MPI_WAIT";
    case Cls::POLL:
      return "MPI_POLL";
    case Cls::ENV:
      break;
  }
  return "MPI";
}

/// A poll in a spin loop costs one record per spin, so polls aggregate unless a selection names
/// one for recording.
CapMode mode_of(const char* name, Cls c) {
  const auto& rt = ConfigurationManager::runtime();
  if (rt.mpi_mode == CapMode::OFF) return CapMode::OFF;
  return ConfigurationManager::mode_for(c == Cls::POLL ? CapMode::AGGREGATE : rt.mpi_mode,
                                        rt.mpi_select, name);
}

template <typename Fn>
Fn pmpi(const char* name) {
  return reinterpret_cast<Fn>(dlsym(RTLD_DEFAULT, name));
}

long long type_size(Hd dt) {
  using Fn = int (*)(Hd, int*);
  static const Fn fn = pmpi<Fn>("PMPI_Type_size");
  int n = 0;
  if (fn == nullptr || fn(dt, &n) != 0 || n < 0) return 0;
  return n;
}

int comm_size(Hd comm) {
  using Fn = int (*)(Hd, int*);
  static const Fn fn = pmpi<Fn>("PMPI_Comm_size");
  int n = 0;
  if (fn == nullptr || fn(comm, &n) != 0) return 0;
  return n;
}

struct FileInfo {
  char fhash[32];
  int comm_size;
};

// Leaked: wrappers still run during exit, after static destructors.
std::unordered_map<Hd, FileInfo>& files() {
  static auto* m = new std::unordered_map<Hd, FileInfo>();
  return *m;
}
std::mutex& files_mu() {
  static auto* m = new std::mutex();
  return *m;
}

FileInfo file_info(Hd fh) {
  std::lock_guard<std::mutex> lock(files_mu());
  const auto it = files().find(fh);
  return it != files().end() ? it->second : FileInfo{{0}, 0};
}

/// Same FH metadata as the posix module, so an MPI-IO record and a pread on the same path share a
/// fhash.
void open_file(Hd fh, const char* path, int nprocs) {
  FileInfo fi{{0}, nprocs};
  datacrumbs::client::PfwSink* s = sink();
  if (path != nullptr && s != nullptr) {
    const std::string h = datacrumbs::pfw::hhash(path);
    std::snprintf(fi.fhash, sizeof(fi.fhash), "%s", h.c_str());
    char line[4096 + 256];
    const int m = std::snprintf(
        line, sizeof(line),
        R"({"name":"FH","cat":"dftracer","type":"metadata","ph":4,"args":{"hhash":"%s","name":"%s","value":"%s"}})"
        "\n",
        s->hhash().c_str(), path, fi.fhash);
    if (m > 0 && static_cast<std::size_t>(m) < sizeof(line))
      s->write(line, static_cast<std::size_t>(m));
  }
  std::lock_guard<std::mutex> lock(files_mu());
  files()[fh] = fi;
}

void close_file(Hd fh) {
  std::lock_guard<std::mutex> lock(files_mu());
  files().erase(fh);
}

/// The file hash rides apart from the numbers: an aggregate sums numbers and drops it.
struct Args {
  NumArg a[datacrumbs::client::kMaxAggArgs];
  int n = 0;
  const char* fhash = nullptr;
  void i(const char* k, long long v) {
    if (n >= datacrumbs::client::kMaxAggArgs - 1) return;  // one slot kept for fhash
    a[n].key = k;
    a[n].kind = NumKind::INT;
    a[n].enum_fn = nullptr;
    a[n++].i = v;
  }
};

void emit(const char* name, Cls c, CapMode mode, std::uint64_t t0, std::uint64_t t1, Args& a) {
  datacrumbs::client::PfwSink* s = sink();
  if (s == nullptr) return;
  if (g_rank >= 0) a.i("rank", g_rank);
  datacrumbs::client::AggSite* site = s->site_cached(name, cat_of(c), DC_TYPE, "gotcha");
  if (site == nullptr) return;
  const std::uint64_t dur = t1 > t0 ? t1 - t0 : 0;
  if (mode == CapMode::AGGREGATE) {
    s->tally(site, t1, dur, a.a, a.n);
    return;
  }
  int n = a.n;
  if (a.fhash != nullptr && *a.fhash != '\0') {
    a.a[n].key = "fhash";
    a.a[n].kind = NumKind::STR;
    std::snprintf(a.a[n].s, sizeof(a.a[n].s), "%s", a.fhash);
    ++n;
  }
  s->record(site, t0, dur, a.a, n);
}

void add_file(Args& a, FileInfo& keep, Hd fh) {
  keep = file_info(fh);
  if (keep.comm_size > 0) a.i("comm_size", keep.comm_size);
  a.fhash = keep.fhash;
}

void add_bytes(Args& a, long long count, Hd dt) {
  a.i("count", count);
  a.i("bytes", count * type_size(dt));
}

long long sum(const int* v, int n) {
  long long t = 0;
  if (v != nullptr)
    for (int k = 0; k < n; ++k) t += v[k];
  return t;
}

}  // namespace

// PRE runs before the clock starts, POST after it stops; both may add to `_a`.
#define DC_MPI(name, cls, proto, call, PRE, POST)                                                  \
  static gotcha_wrappee_handle_t g_h_##name;                                                       \
  static int name##_dcwrap proto {                                                                 \
    using Fn = int(*) proto;                                                                       \
    static const char* const kName = #name;                                                        \
    static Fn real = nullptr;                                                                      \
    if (real == nullptr)                                                                           \
      real = reinterpret_cast<Fn>(datacrumbs::client::gotcha_wrap::real_of(                        \
          g_h_##name, kName, reinterpret_cast<void*>(&name##_dcwrap)));                            \
    if (real == nullptr) return -1;                                                                \
    static const CapMode mode = mode_of(kName, Cls::cls);                                          \
    if (mode == CapMode::OFF || g_torn_down || sink() == nullptr) return real call;                \
    Reentry _g;                                                                                    \
    if (!_g.entered) return real call;                                                             \
    Args _a;                                                                                       \
    [[maybe_unused]] FileInfo _fi;                                                                 \
    PRE;                                                                                           \
    const std::uint64_t _t0 = datacrumbs::client::mono_ns();                                       \
    const int _rc = real call;                                                                     \
    const std::uint64_t _t1 = datacrumbs::client::mono_ns();                                       \
    POST;                                                                                          \
    if (_rc != 0) _a.i("rc", _rc);                                                                 \
    emit(kName, Cls::cls, mode, _t0, _t1, _a);                                                     \
    return _rc;                                                                                    \
  }

#define DC_NONE (void)0

// MPI-IO. Offsets are in etype units relative to the current view, as the caller passed them.
DC_MPI(MPI_File_open, FILE, (Hd comm, const char* path, int amode, Hd info, Hd* fh),
       (comm, path, amode, info, fh), (_a.i("amode", amode), _a.i("comm_size", comm_size(comm))),
       if (_rc == 0 && fh != nullptr) {
         open_file(*fh, path, comm_size(comm));
         _fi = file_info(*fh);
         _a.fhash = _fi.fhash;
       })
// The handle is read before the call: close sets it to MPI_FILE_NULL.
DC_MPI(MPI_File_close, FILE, (Hd * fh), (fh), (fh != nullptr ? add_file(_a, _fi, *fh) : (void)0);
       Hd _fh = fh != nullptr ? *fh : nullptr, if (_rc == 0) close_file(_fh))
DC_MPI(MPI_File_set_view, FILE,
       (Hd fh, long long disp, Hd etype, Hd ftype, const char* rep, Hd info),
       (fh, disp, etype, ftype, rep, info),
       (_a.i("disp", disp), _a.i("etype_size", type_size(etype)), add_file(_a, _fi, fh)), DC_NONE)
DC_MPI(MPI_File_sync, FILE, (Hd fh), (fh), add_file(_a, _fi, fh), DC_NONE)

#define DC_MPI_IO_AT(name)                                                                         \
  DC_MPI(name, FILE, (Hd fh, long long off, void* buf, int count, Hd dt, void* st),                \
         (fh, off, buf, count, dt, st), (_a.i("offset", off), add_bytes(_a, count, dt),            \
                                         add_file(_a, _fi, fh)),                                   \
         DC_NONE)
#define DC_MPI_IO(name)                                                                            \
  DC_MPI(name, FILE, (Hd fh, void* buf, int count, Hd dt, void* st), (fh, buf, count, dt, st),     \
         (add_bytes(_a, count, dt), add_file(_a, _fi, fh)), DC_NONE)

DC_MPI_IO_AT(MPI_File_read_at)
DC_MPI_IO_AT(MPI_File_read_at_all)
DC_MPI_IO_AT(MPI_File_write_at)
DC_MPI_IO_AT(MPI_File_write_at_all)
DC_MPI_IO(MPI_File_read)
DC_MPI_IO(MPI_File_read_all)
DC_MPI_IO(MPI_File_write)
DC_MPI_IO(MPI_File_write_all)

// Collectives. bytes is what this rank contributes: sent for the gathers and all-to-alls, the
// buffer for broadcast and reductions, received for the scatters.
DC_MPI(MPI_Barrier, COLL, (Hd comm), (comm), _a.i("comm_size", comm_size(comm)), DC_NONE)
DC_MPI(MPI_Ibarrier, COLL, (Hd comm, Hd req), (comm, req), _a.i("comm_size", comm_size(comm)),
       DC_NONE)
DC_MPI(MPI_Bcast, COLL, (void* buf, int count, Hd dt, int root, Hd comm),
       (buf, count, dt, root, comm),
       (add_bytes(_a, count, dt), _a.i("root", root), _a.i("comm_size", comm_size(comm))),
       DC_NONE)
DC_MPI(MPI_Allreduce, COLL, (const void* s, void* r, int count, Hd dt, Hd op, Hd comm),
       (s, r, count, dt, op, comm), (add_bytes(_a, count, dt), _a.i("comm_size", comm_size(comm))),
       DC_NONE)
DC_MPI(MPI_Reduce, COLL, (const void* s, void* r, int count, Hd dt, Hd op, int root, Hd comm),
       (s, r, count, dt, op, root, comm),
       (add_bytes(_a, count, dt), _a.i("root", root), _a.i("comm_size", comm_size(comm))),
       DC_NONE)
DC_MPI(MPI_Alltoall, COLL, (const void* s, int sc, Hd st, void* r, int rc, Hd rt, Hd comm),
       (s, sc, st, r, rc, rt, comm), const int _p = comm_size(comm);
       (add_bytes(_a, static_cast<long long>(sc) * _p, st), _a.i("comm_size", _p)), DC_NONE)
DC_MPI(MPI_Alltoallv, COLL,
       (const void* s, const int* sc, const int* sd, Hd st, void* r, const int* rc, const int* rd,
        Hd rt, Hd comm),
       (s, sc, sd, st, r, rc, rd, rt, comm), const int _p = comm_size(comm);
       (add_bytes(_a, sum(sc, _p), st), _a.i("comm_size", _p)), DC_NONE)
DC_MPI(MPI_Allgather, COLL, (const void* s, int sc, Hd st, void* r, int rc, Hd rt, Hd comm),
       (s, sc, st, r, rc, rt, comm), (add_bytes(_a, sc, st), _a.i("comm_size", comm_size(comm))),
       DC_NONE)
DC_MPI(MPI_Allgatherv, COLL,
       (const void* s, int sc, Hd st, void* r, const int* rc, const int* dp, Hd rt, Hd comm),
       (s, sc, st, r, rc, dp, rt, comm),
       (add_bytes(_a, sc, st), _a.i("comm_size", comm_size(comm))), DC_NONE)
DC_MPI(MPI_Gather, COLL,
       (const void* s, int sc, Hd st, void* r, int rc, Hd rt, int root, Hd comm),
       (s, sc, st, r, rc, rt, root, comm),
       (add_bytes(_a, sc, st), _a.i("root", root), _a.i("comm_size", comm_size(comm))), DC_NONE)
DC_MPI(MPI_Gatherv, COLL,
       (const void* s, int sc, Hd st, void* r, const int* rc, const int* dp, Hd rt, int root,
        Hd comm),
       (s, sc, st, r, rc, dp, rt, root, comm),
       (add_bytes(_a, sc, st), _a.i("root", root), _a.i("comm_size", comm_size(comm))), DC_NONE)
DC_MPI(MPI_Scatter, COLL,
       (const void* s, int sc, Hd st, void* r, int rc, Hd rt, int root, Hd comm),
       (s, sc, st, r, rc, rt, root, comm),
       (add_bytes(_a, rc, rt), _a.i("root", root), _a.i("comm_size", comm_size(comm))), DC_NONE)
DC_MPI(MPI_Scatterv, COLL,
       (const void* s, const int* sc, const int* dp, Hd st, void* r, int rc, Hd rt, int root,
        Hd comm),
       (s, sc, dp, st, r, rc, rt, root, comm),
       (add_bytes(_a, rc, rt), _a.i("root", root), _a.i("comm_size", comm_size(comm))), DC_NONE)

// Point to point. A nonblocking call's record is the post; its completion is the wait's.
DC_MPI(MPI_Send, P2P, (const void* b, int c, Hd dt, int peer, int tag, Hd comm),
       (b, c, dt, peer, tag, comm), (add_bytes(_a, c, dt), _a.i("peer", peer), _a.i("tag", tag)),
       DC_NONE)
DC_MPI(MPI_Recv, P2P, (void* b, int c, Hd dt, int peer, int tag, Hd comm, void* st),
       (b, c, dt, peer, tag, comm, st),
       (add_bytes(_a, c, dt), _a.i("peer", peer), _a.i("tag", tag)), DC_NONE)
DC_MPI(MPI_Isend, P2P, (const void* b, int c, Hd dt, int peer, int tag, Hd comm, Hd req),
       (b, c, dt, peer, tag, comm, req),
       (add_bytes(_a, c, dt), _a.i("peer", peer), _a.i("tag", tag)), DC_NONE)
DC_MPI(MPI_Issend, P2P, (const void* b, int c, Hd dt, int peer, int tag, Hd comm, Hd req),
       (b, c, dt, peer, tag, comm, req),
       (add_bytes(_a, c, dt), _a.i("peer", peer), _a.i("tag", tag)), DC_NONE)
DC_MPI(MPI_Irecv, P2P, (void* b, int c, Hd dt, int peer, int tag, Hd comm, Hd req),
       (b, c, dt, peer, tag, comm, req),
       (add_bytes(_a, c, dt), _a.i("peer", peer), _a.i("tag", tag)), DC_NONE)

DC_MPI(MPI_Wait, WAIT, (Hd req, void* st), (req, st), DC_NONE, DC_NONE)
DC_MPI(MPI_Waitall, WAIT, (int n, Hd reqs, void* sts), (n, reqs, sts), _a.i("n", n), DC_NONE)
DC_MPI(MPI_Waitany, WAIT, (int n, Hd reqs, int* idx, void* st), (n, reqs, idx, st), _a.i("n", n),
       DC_NONE)
DC_MPI(MPI_Waitsome, WAIT, (int n, Hd reqs, int* outc, int* idx, void* sts),
       (n, reqs, outc, idx, sts), _a.i("n", n),
       if (outc != nullptr) _a.i("done", *outc))

// Polls: `hit` sums to how many polls found something, so an aggregate still says how long a
// spin ran empty.
DC_MPI(MPI_Test, POLL, (Hd req, int* flag, void* st), (req, flag, st), DC_NONE,
       _a.i("hit", flag != nullptr && *flag != 0))
DC_MPI(MPI_Testall, POLL, (int n, Hd reqs, int* flag, void* sts), (n, reqs, flag, sts), DC_NONE,
       _a.i("hit", flag != nullptr && *flag != 0))
DC_MPI(MPI_Testany, POLL, (int n, Hd reqs, int* idx, int* flag, void* st),
       (n, reqs, idx, flag, st), DC_NONE, _a.i("hit", flag != nullptr && *flag != 0))
DC_MPI(MPI_Testsome, POLL, (int n, Hd reqs, int* outc, int* idx, void* sts),
       (n, reqs, outc, idx, sts), DC_NONE, _a.i("hit", outc != nullptr && *outc > 0))
DC_MPI(MPI_Iprobe, POLL, (int src, int tag, Hd comm, int* flag, void* st),
       (src, tag, comm, flag, st), DC_NONE, _a.i("hit", flag != nullptr && *flag != 0))

// The sink outlives this: datacrumbs_fini runs at exit, after it.
DC_MPI(MPI_Finalize, ENV, (void), (), DC_NONE, DC_NONE)

#define DC_BIND(name) {#name, reinterpret_cast<void*>(name##_dcwrap), &g_h_##name}

void datacrumbs::client::mpi::init() {
  if (!ConfigurationManager::runtime().mpi_enabled) return;
  if (datacrumbs::Singleton<MpiSink>::get_instance() == nullptr) return;
  static gotcha_binding_t bindings[] = {
      DC_BIND(MPI_File_open),     DC_BIND(MPI_File_close),        DC_BIND(MPI_File_set_view),
      DC_BIND(MPI_File_sync),     DC_BIND(MPI_File_read_at),      DC_BIND(MPI_File_read_at_all),
      DC_BIND(MPI_File_write_at), DC_BIND(MPI_File_write_at_all), DC_BIND(MPI_File_read),
      DC_BIND(MPI_File_read_all), DC_BIND(MPI_File_write),        DC_BIND(MPI_File_write_all),
      DC_BIND(MPI_Barrier),       DC_BIND(MPI_Ibarrier),          DC_BIND(MPI_Bcast),
      DC_BIND(MPI_Allreduce),     DC_BIND(MPI_Reduce),            DC_BIND(MPI_Alltoall),
      DC_BIND(MPI_Alltoallv),     DC_BIND(MPI_Allgather),         DC_BIND(MPI_Allgatherv),
      DC_BIND(MPI_Gather),        DC_BIND(MPI_Gatherv),           DC_BIND(MPI_Scatter),
      DC_BIND(MPI_Scatterv),      DC_BIND(MPI_Send),              DC_BIND(MPI_Recv),
      DC_BIND(MPI_Isend),         DC_BIND(MPI_Issend),            DC_BIND(MPI_Irecv),
      DC_BIND(MPI_Wait),          DC_BIND(MPI_Waitall),           DC_BIND(MPI_Waitany),
      DC_BIND(MPI_Waitsome),      DC_BIND(MPI_Test),              DC_BIND(MPI_Testall),
      DC_BIND(MPI_Testany),       DC_BIND(MPI_Testsome),          DC_BIND(MPI_Iprobe),
      DC_BIND(MPI_Finalize),
  };
  const int n = static_cast<int>(sizeof(bindings) / sizeof(bindings[0]));
  // A non-MPI process links none of these, so not-found is the normal case there.
  const gotcha_error_t rc = ::gotcha_wrap(bindings, n, "datacrumbs_mpi");
  if (rc != GOTCHA_SUCCESS && rc != GOTCHA_FUNCTION_NOT_FOUND)
    DC_LOG_ERROR("[mpi] gotcha_wrap failed: %d", static_cast<int>(rc));
  if (ConfigurationManager::runtime().mpi_debug) {
    int bound = 0;
    for (const auto& b : bindings)
      if (gotcha_get_wrappee(*b.function_handle) != nullptr) ++bound;
    DC_LOG_INFO("[mpi] gotcha_wrap rc=%d bound=%d of %d", static_cast<int>(rc), bound, n);
  }
}

void datacrumbs::client::mpi::on_init(const char* name, std::uint64_t t0_ns, std::uint64_t t1_ns,
                                      int rank, int size) {
  g_rank = rank;
  if (g_torn_down || sink() == nullptr) return;
  const CapMode mode = mode_of(name, Cls::ENV);
  if (mode == CapMode::OFF) return;
  Args a;
  if (size > 0) a.i("comm_size", size);
  emit(name, Cls::ENV, mode, t0_ns, t1_ns, a);
}

void datacrumbs::client::mpi::fini() {
  g_torn_down = true;
  datacrumbs::Singleton<MpiSink>::finalize();
}
