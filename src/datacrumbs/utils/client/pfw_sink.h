// SPDX-License-Identifier: MIT

#ifndef DATACRUMBS_UTILS_CLIENT_PFW_SINK_H
#define DATACRUMBS_UTILS_CLIENT_PFW_SINK_H

#include <datacrumbs/common/pfw_format.h>
#include <datacrumbs/utils/timesync/timesync_reader.h>
#include <sys/stat.h>
#include <unistd.h>

#include <atomic>
#include <cerrno>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <mutex>
#include <string>

namespace datacrumbs::client {

/**
 * @brief Per-process .pfw.gz sink for records a client emits from userspace.
 *
 * Buffers NDJSON lines and writes one gzip member per flush. Remap timestamps through clock() to
 * put them on the dc_timesync global epoch, which is what merges these records with the server
 * trace. Thread-safe. A record is not durable until flush() or the 256 KB threshold.
 */
class PfwSink {
 public:
  /// Writes <dir>/trace-<tag>-<pid>-<host>.pfw.gz, taking <dir> from @p dir_env, else
  /// DATACRUMBS_LOG_DIR, else /tmp. Terminates the process if the file cannot be opened: capture is
  /// opt-in, so a sink that silently drops every record is indistinguishable from an empty run.
  PfwSink(const char* tag, const char* dir_env) {
    reader_.map();
    char host[256] = {0};
    gethostname(host, sizeof(host) - 1);
    hhash_ = datacrumbs::pfw::hhash(host);

    const char* dir = dir_env != nullptr ? std::getenv(dir_env) : nullptr;
    if (dir == nullptr || *dir == '\0') dir = std::getenv("DATACRUMBS_LOG_DIR");
    if (dir == nullptr || *dir == '\0') dir = "/tmp";
    mkdir(dir, 0755);  // callers pass a per-run dir; without this fopen just fails

    char path[1024];
    std::snprintf(path, sizeof(path), "%s/trace-%s-%d-%s.pfw.gz", dir, tag, getpid(), host);
    file_ = std::fopen(path, "wb");
    if (file_ == nullptr) {
      std::fprintf(stderr, "[dc-%s] FATAL: cannot open %s: %s\n", tag, path, std::strerror(errno));
      _exit(1);
    }

    char hh[512];
    const int n = std::snprintf(
        hh, sizeof(hh),
        R"({"name":"HH","cat":"dftracer","type":"metadata","ph":4,"args":{"hhash":"%s","name":"%s","value":"%s"}})"
        "\n",
        hhash_.c_str(), host, hhash_.c_str());
    buf_.append(hh, static_cast<std::size_t>(n));
    flush_locked();  // HH as its own member, matching the server writer's layout
  }

  ~PfwSink() {
    flush();
    if (file_ != nullptr) std::fclose(file_);
  }

  PfwSink(const PfwSink&) = delete;
  PfwSink& operator=(const PfwSink&) = delete;

  void write(const char* line, std::size_t n) {
    std::lock_guard<std::mutex> lock(mu_);
    buf_.append(line, n);
    if (buf_.size() >= kFlushBytes) flush_locked();
  }

  void flush() {
    std::lock_guard<std::mutex> lock(mu_);
    flush_locked();
  }

  std::uint64_t next_id() { return id_.fetch_add(1); }
  const std::string& hhash() const { return hhash_; }
  const datacrumbs::timesync::Reader& clock() const { return reader_; }

 private:
  static constexpr std::size_t kFlushBytes = 256 * 1024;

  void flush_locked() {
    if (buf_.empty() || file_ == nullptr) return;
    const std::vector<uint8_t> member = datacrumbs::pfw::gzip_block(buf_);
    std::fwrite(member.data(), 1, member.size(), file_);
    std::fflush(file_);
    buf_.clear();
  }

  datacrumbs::timesync::Reader reader_;
  std::string hhash_;
  std::mutex mu_;
  std::string buf_;
  std::FILE* file_ = nullptr;
  std::atomic<std::uint64_t> id_{0};
};

}  // namespace datacrumbs::client

#endif  // DATACRUMBS_UTILS_CLIENT_PFW_SINK_H
