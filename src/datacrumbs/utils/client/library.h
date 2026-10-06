// SPDX-License-Identifier: MIT

#ifndef DATACRUMBS_LIBRARY_H
#define DATACRUMBS_LIBRARY_H

/// Emits the program's begin marker.
extern "C" __attribute__((visibility("default"))) void datacrumbs_start();

/// Emits the program's end marker. Idempotent.
extern "C" __attribute__((visibility("default"))) void datacrumbs_stop();

/// Runs when this shared library loads.
extern void __attribute__((constructor)) datacrumbs_init(void);

/// Runs when this shared library unloads.
extern void __attribute__((destructor)) datacrumbs_fini(void);

#endif  // DATACRUMBS_LIBRARY_H