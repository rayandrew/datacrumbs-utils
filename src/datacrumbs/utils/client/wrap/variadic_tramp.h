// SPDX-License-Identifier: MIT

#ifndef DATACRUMBS_UTILS_CLIENT_VARIADIC_TRAMP_H
#define DATACRUMBS_UTILS_CLIENT_VARIADIC_TRAMP_H

/**
 * @brief Records calls no ordinary wrapper can forward: variadic functions, and undeclared ones.
 * AAPCS64 calls variadic and non-variadic functions differently, and a v-form forwarder (vprintf
 * for printf) is not always available; an undeclared symbol has no prototype at all.
 */

extern "C" void* dc_tramp_enter(const char* name, void** slot, void* ret, void* sp, void** lr_out);
extern "C" void* dc_tramp_exit(void* sp);
// Hidden so adrp with :lo12: can reach it: a default-visibility symbol in a shared library is
// preemptible and has to go through the GOT.
extern "C" __attribute__((visibility("hidden"))) void dc_tramp_return_thunk();

#if defined(__aarch64__)

// x0-x7 and q0-q7 are argument registers; x8 carries the indirect result location for a large
// struct return. 224 bytes covers all of them plus the frame record, 16-byte aligned. Offset 88
// carries the link register dc_tramp_enter chose. x16/x17 hold the target and that link register
// across the restores: both are call-clobbered scratch, safe since nothing runs before the branch.
#define DC_VARIADIC_TRAMP(sym)                                       \
  extern "C" __attribute__((visibility("hidden"))) void* sym##_real; \
  void* sym##_real = nullptr;                                        \
  asm(".text\n"                                                      \
      ".globl " #sym                                                 \
      "\n"                                                           \
      ".type " #sym ", %function\n" #sym                             \
      ":\n"                                                          \
      "  .cfi_startproc\n"                                           \
      "  stp x29, x30, [sp, #-224]!\n"                               \
      "  .cfi_def_cfa_offset 224\n"                                  \
      "  .cfi_offset 29, -224\n"                                     \
      "  .cfi_offset 30, -216\n"                                     \
      "  mov x29, sp\n"                                              \
      "  stp x0, x1, [sp, #16]\n"                                    \
      "  stp x2, x3, [sp, #32]\n"                                    \
      "  stp x4, x5, [sp, #48]\n"                                    \
      "  stp x6, x7, [sp, #64]\n"                                    \
      "  str x8, [sp, #80]\n"                                        \
      "  stp q0, q1, [sp, #96]\n"                                    \
      "  stp q2, q3, [sp, #128]\n"                                   \
      "  stp q4, q5, [sp, #160]\n"                                   \
      "  stp q6, q7, [sp, #192]\n"                                   \
      "  adrp x0, " #sym                                             \
      "_name\n"                                                      \
      "  add x0, x0, :lo12:" #sym                                    \
      "_name\n"                                                      \
      "  adrp x1, " #sym                                             \
      "_real\n"                                                      \
      "  add x1, x1, :lo12:" #sym                                    \
      "_real\n"                                                      \
      "  ldr x2, [sp, #8]\n"                                         \
      "  add x3, sp, #224\n"                                         \
      "  add x4, sp, #88\n"                                          \
      "  bl dc_tramp_enter\n"                                        \
      "  mov x16, x0\n"                                              \
      "  ldr x17, [sp, #88]\n"                                       \
      "  ldp q6, q7, [sp, #192]\n"                                   \
      "  ldp q4, q5, [sp, #160]\n"                                   \
      "  ldp q2, q3, [sp, #128]\n"                                   \
      "  ldp q0, q1, [sp, #96]\n"                                    \
      "  ldr x8, [sp, #80]\n"                                        \
      "  ldp x6, x7, [sp, #64]\n"                                    \
      "  ldp x4, x5, [sp, #48]\n"                                    \
      "  ldp x2, x3, [sp, #32]\n"                                    \
      "  ldp x0, x1, [sp, #16]\n"                                    \
      "  ldp x29, x30, [sp], #224\n"                                 \
      "  .cfi_def_cfa_offset 0\n"                                    \
      "  .cfi_restore 29\n"                                          \
      "  .cfi_restore 30\n"                                          \
      "  mov x30, x17\n"                                             \
      "  br x16\n"                                                   \
      "  .cfi_endproc\n"                                             \
      ".size " #sym ", .-" #sym                                      \
      "\n"                                                           \
      ".section .rodata\n" #sym                                      \
      "_name:\n"                                                     \
      "  .asciz \"" #sym                                             \
      "\"\n"                                                         \
      ".text\n")

// Where a hooked call returns. The callee has restored the stack, so the stack pointer here is the
// one recorded at entry, which is what identifies the frame. Return values live in x0-x7 and q0-q7
// and have to survive the bookkeeping. Defined once, by DC_TRAMP_RETURN_THUNK().
#define DC_TRAMP_RETURN_THUNK()                  \
  asm(".text\n"                                  \
      ".globl dc_tramp_return_thunk\n"           \
      ".hidden dc_tramp_return_thunk\n"          \
      ".type dc_tramp_return_thunk, %function\n" \
      "dc_tramp_return_thunk:\n"                 \
      "  .cfi_startproc\n"                       \
      "  .cfi_undefined 30\n"                    \
      "  stp x29, x30, [sp, #-224]!\n"           \
      "  .cfi_def_cfa_offset 224\n"              \
      "  mov x29, sp\n"                          \
      "  stp x0, x1, [sp, #16]\n"                \
      "  stp x2, x3, [sp, #32]\n"                \
      "  stp x4, x5, [sp, #48]\n"                \
      "  stp x6, x7, [sp, #64]\n"                \
      "  str x8, [sp, #80]\n"                    \
      "  stp q0, q1, [sp, #96]\n"                \
      "  stp q2, q3, [sp, #128]\n"               \
      "  stp q4, q5, [sp, #160]\n"               \
      "  stp q6, q7, [sp, #192]\n"               \
      "  add x0, sp, #224\n"                     \
      "  bl dc_tramp_exit\n"                     \
      "  mov x16, x0\n"                          \
      "  ldp q6, q7, [sp, #192]\n"               \
      "  ldp q4, q5, [sp, #160]\n"               \
      "  ldp q2, q3, [sp, #128]\n"               \
      "  ldp q0, q1, [sp, #96]\n"                \
      "  ldr x8, [sp, #80]\n"                    \
      "  ldp x6, x7, [sp, #64]\n"                \
      "  ldp x4, x5, [sp, #48]\n"                \
      "  ldp x2, x3, [sp, #32]\n"                \
      "  ldp x0, x1, [sp, #16]\n"                \
      "  ldp x29, x30, [sp], #224\n"             \
      "  .cfi_def_cfa_offset 0\n"                \
      "  br x16\n"                               \
      "  .cfi_endproc\n"                         \
      ".size dc_tramp_return_thunk, .-dc_tramp_return_thunk\n")

#elif defined(__x86_64__)

// rdi rsi rdx rcx r8 r9 carry integer args, xmm0-7 the floating ones, al the vector
// register count a variadic callee reads. Subtracting 216 keeps rsp 16-byte aligned.
// The return address sits at the stack pointer once our frame is gone, with stack args
// above it, so overwriting that slot hooks the return and leaves the callee's frame intact.
#define DC_VARIADIC_TRAMP(sym)                                       \
  extern "C" __attribute__((visibility("hidden"))) void* sym##_real; \
  void* sym##_real = nullptr;                                        \
  asm(".text\n"                                                      \
      ".globl " #sym                                                 \
      "\n"                                                           \
      ".type " #sym ", @function\n" #sym                             \
      ":\n"                                                          \
      "  .cfi_startproc\n"                                           \
      "  subq $216, %rsp\n"                                          \
      "  .cfi_def_cfa_offset 224\n"                                  \
      "  movq %rdi, 0(%rsp)\n"                                       \
      "  movq %rsi, 8(%rsp)\n"                                       \
      "  movq %rdx, 16(%rsp)\n"                                      \
      "  movq %rcx, 24(%rsp)\n"                                      \
      "  movq %r8, 32(%rsp)\n"                                       \
      "  movq %r9, 40(%rsp)\n"                                       \
      "  movq %rax, 48(%rsp)\n"                                      \
      "  movaps %xmm0, 64(%rsp)\n"                                   \
      "  movaps %xmm1, 80(%rsp)\n"                                   \
      "  movaps %xmm2, 96(%rsp)\n"                                   \
      "  movaps %xmm3, 112(%rsp)\n"                                  \
      "  movaps %xmm4, 128(%rsp)\n"                                  \
      "  movaps %xmm5, 144(%rsp)\n"                                  \
      "  movaps %xmm6, 160(%rsp)\n"                                  \
      "  movaps %xmm7, 176(%rsp)\n"                                  \
      "  leaq " #sym                                                 \
      "_name(%rip), %rdi\n"                                          \
      "  leaq " #sym                                                 \
      "_real(%rip), %rsi\n"                                          \
      "  movq 216(%rsp), %rdx\n"                                     \
      "  leaq 224(%rsp), %rcx\n"                                     \
      "  leaq 56(%rsp), %r8\n"                                       \
      "  xorl %eax, %eax\n"                                          \
      "  call dc_tramp_enter\n"                                      \
      "  movq %rax, %r11\n"                                          \
      "  movq 56(%rsp), %r10\n"                                      \
      "  movaps 176(%rsp), %xmm7\n"                                  \
      "  movaps 160(%rsp), %xmm6\n"                                  \
      "  movaps 144(%rsp), %xmm5\n"                                  \
      "  movaps 128(%rsp), %xmm4\n"                                  \
      "  movaps 112(%rsp), %xmm3\n"                                  \
      "  movaps 96(%rsp), %xmm2\n"                                   \
      "  movaps 80(%rsp), %xmm1\n"                                   \
      "  movaps 64(%rsp), %xmm0\n"                                   \
      "  movq 48(%rsp), %rax\n"                                      \
      "  movq 40(%rsp), %r9\n"                                       \
      "  movq 32(%rsp), %r8\n"                                       \
      "  movq 24(%rsp), %rcx\n"                                      \
      "  movq 16(%rsp), %rdx\n"                                      \
      "  movq 8(%rsp), %rsi\n"                                       \
      "  movq 0(%rsp), %rdi\n"                                       \
      "  addq $216, %rsp\n"                                          \
      "  .cfi_def_cfa_offset 8\n"                                    \
      "  movq %r10, (%rsp)\n"                                        \
      "  jmp *%r11\n"                                                \
      "  .cfi_endproc\n"                                             \
      ".size " #sym ", .-" #sym                                      \
      "\n"                                                           \
      ".section .rodata\n" #sym                                      \
      "_name:\n"                                                     \
      "  .asciz \"" #sym                                             \
      "\"\n"                                                         \
      ".text\n")

// The callee's ret popped our address, so the stack pointer here identifies the frame.
// fxsave, not hand-saved registers: a long double return lives in st(0), and naming
// registers would assume what the traced set returns. It needs 512 bytes 16-byte
// aligned; 528 keeps the call aligned and leaves room for the two integer return regs.
#define DC_TRAMP_RETURN_THUNK()                  \
  asm(".text\n"                                  \
      ".globl dc_tramp_return_thunk\n"           \
      ".hidden dc_tramp_return_thunk\n"          \
      ".type dc_tramp_return_thunk, @function\n" \
      "dc_tramp_return_thunk:\n"                 \
      "  .cfi_startproc\n"                       \
      "  .cfi_def_cfa_offset 0\n"                \
      "  .cfi_undefined 16\n"                    \
      "  subq $544, %rsp\n"                      \
      "  .cfi_def_cfa_offset 544\n"              \
      "  movq %rax, 0(%rsp)\n"                   \
      "  movq %rdx, 8(%rsp)\n"                   \
      "  fxsave 16(%rsp)\n"                      \
      "  leaq 544(%rsp), %rdi\n"                 \
      "  call dc_tramp_exit\n"                   \
      "  movq %rax, %r11\n"                      \
      "  fxrstor 16(%rsp)\n"                     \
      "  movq 8(%rsp), %rdx\n"                   \
      "  movq 0(%rsp), %rax\n"                   \
      "  addq $544, %rsp\n"                      \
      "  .cfi_def_cfa_offset 0\n"                \
      "  jmp *%r11\n"                            \
      "  .cfi_endproc\n"                         \
      ".size dc_tramp_return_thunk, .-dc_tramp_return_thunk\n")

#else
#error "no variadic trampoline for this architecture"
#endif

#endif  // DATACRUMBS_UTILS_CLIENT_VARIADIC_TRAMP_H
