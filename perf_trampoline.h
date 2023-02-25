#ifndef RUBY_VM_PERF_TRAMPOLINE_H
#define RUBY_VM_PERF_TRAMPOLINE_H

#include "vm_core.h"

struct perf_trampoline_allocator *rb_perf_trampoline_allocator_init(void);
void rb_perf_trampoline_allocator_destroy(struct perf_trampoline_allocator *al);
void Init_perf_trampoline_debug(void);

#endif
