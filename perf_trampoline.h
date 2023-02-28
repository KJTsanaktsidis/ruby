#ifndef RUBY_VM_PERF_TRAMPOLINE_H
#define RUBY_VM_PERF_TRAMPOLINE_H

#include "vm_core.h"

typedef VALUE (*perf_trampoline_t)(rb_execution_context_t *, rb_control_frame_t *);

void rb_perf_trampoline_initialize(void);
void rb_perf_trampoline_deinitialize(void);
bool rb_perf_trampoline_enabled_p(void);
perf_trampoline_t rb_perf_trampoline_allocate(void *trampoline_target);
void rb_perf_trampoline_free(perf_trampoline_t trampoline);
void Init_perf_trampoline_debug(void);

#endif
