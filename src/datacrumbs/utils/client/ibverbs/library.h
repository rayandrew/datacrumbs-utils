// SPDX-License-Identifier: MIT

#ifndef DATACRUMBS_UTILS_CLIENT_IBVERBS_LIBRARY_H
#define DATACRUMBS_UTILS_CLIENT_IBVERBS_LIBRARY_H

namespace datacrumbs::client::ibverbs {

/// Interpose completion-queue creation so RDMA completions can be read with their hardware
/// timestamps. Reads DATACRUMBS_ENV_HWTS and returns immediately when it is off.
void init();

/// Flush and close. Safe when init did nothing.
void fini();

/// Write what the per-thread rings hold, for a SIGTERM that runs no destructor. Call after the
/// background workers stop; safe when init did nothing.
void drain_for_exit();

}  // namespace datacrumbs::client::ibverbs

#endif  // DATACRUMBS_UTILS_CLIENT_IBVERBS_LIBRARY_H
