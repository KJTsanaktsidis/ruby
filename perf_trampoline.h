#ifndef RUBY_VM_PERF_TRAMPOLINE_H
#define RUBY_VM_PERF_TRAMPOLINE_H

#include "vm_core.h"

void Init_perf_trampoline_allocator(rb_vm_t *vm);
void Init_perf_trampoline_debug(void);

#endif
