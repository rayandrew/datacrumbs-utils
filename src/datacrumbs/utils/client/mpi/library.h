// SPDX-License-Identifier: MIT

#ifndef DATACRUMBS_UTILS_CLIENT_MPI_LIBRARY_H
#define DATACRUMBS_UTILS_CLIENT_MPI_LIBRARY_H

#include <cstdint>

namespace datacrumbs::client::mpi {

/// Wrap the public MPI and MPI-IO calls and open this module's sink. Returns at once unless
/// DATACRUMBS_MPI is on.
void init();

/// Records MPI_Init or MPI_Init_thread. Those two are preload definitions in the client, not GOTCHA
/// bindings, so they report here. @p name must be a string literal.
void on_init(const char* name, std::uint64_t t0_ns, std::uint64_t t1_ns, int rank, int size);

/// Flush and close. Safe when init did nothing.
void fini();

}  // namespace datacrumbs::client::mpi

#endif  // DATACRUMBS_UTILS_CLIENT_MPI_LIBRARY_H
