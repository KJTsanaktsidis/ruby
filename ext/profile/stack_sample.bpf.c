#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#include "stack_sample.bpf.h"

char LICENSE[] SEC("license") = "Dual MIT/GPL";

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, STACK_SAMPLE_RINGBUF_SIZE_BYTES);
} events SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, STACK_SAMPLE_THREAD_MAP_ENTRIES);
    __type(key, pid_t);
    __type(value, struct stack_sample_per_thread_data);
} thread_pids SEC(".maps");

uintptr_t ruby_current_vm_ptr = 0;

SEC("perf_event")
int
stack_sample(struct bpf_perf_event_data *ctx)
{
    struct stack_sample_entry *event;

    event = bpf_ringbuf_reserve(&events, sizeof(struct stack_sample_entry), 0);
    if (!event) {
        return 1;
    }
    event->pid = bpf_get_current_pid_tgid() >> 32;
    event->cpu_id = bpf_get_smp_processor_id();
    event->sample_period = ctx->sample_period;

    bpf_ringbuf_submit(event, 0);
    return 0;
}
