#ifndef __STACK_SAMPLE__BPF__H
#define __STACK_SAMPLE__BPF__H

#define STACK_SAMPLE_RINGBUF_SIZE_BYTES (256 * 1024)
#define STACK_SAMPLE_THREAD_MAP_ENTRIES 4096

struct stack_sample_entry {
    __u32 pid;
    __u32 cpu_id;
    __u64 sample_period;
    __u64 vm_value;
};

struct stack_sample_per_thread_data {
    pid_t pid;
    uintptr_t ruby_stack_ptr;
};

#endif

