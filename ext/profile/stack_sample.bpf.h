#ifndef __STACK_SAMPLE__BPF__H
#define __STACK_SAMPLE__BPF__H

struct stack_sample_entry {
    __u32 pid;
    __u32 cpu_id;
    __u64 sample_period;
    __u64 vm_value;
};

#endif

