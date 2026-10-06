// SPDX-License-Identifier: MIT

// Trampolines for the variadic symbols the wrap list cannot cover. One definition per symbol,
// generated from the same pass that skipped them, so the two lists cannot drift.

#include <datacrumbs/utils/client/wrap/variadic_tramp.h>

// Once, not per symbol: every hooked call returns through the same thunk.
DC_TRAMP_RETURN_THUNK();

#include "datacrumbs/utils/client/api_tramp_list.h"

#define T(name, cls) DC_VARIADIC_TRAMP(name);
DC_TRAMP_FUNCS(T)
#undef T
#undef DC_TRAMP_FUNCS

// Symbols the inventory classifies but no header declares. Same mechanism: a trampoline forwards
// by leaving the registers and the stack exactly as the caller left them, so it needs no prototype.
#include "datacrumbs/utils/client/api_undeclared_list.h"

#define T(name, cls) DC_VARIADIC_TRAMP(name);
DC_TRAMP_FUNCS(T)
#undef T
