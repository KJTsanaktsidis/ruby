#ifndef __PERF_HELPER_PROXY_H
#define __PERF_HELPER_PROXY_H

#include <ruby.h>
#include <sys/types.h>

extern VALUE cPerfHelperProxy;
struct PerfHelperProxy;


VALUE perf_helper_proxy_new(void);
void perf_helper_proxy_close(VALUE self);

enum perf_helper_proxy_event_type {
    PERF_HELPER_PROXY_EVENT_NONE,
    PERF_HELPER_PROXY_EVENT_SETUP_DONE,
    PERF_HELPER_PROXY_EVENT_NEWTHREAD_DONE,
    PERF_HELPER_PROXY_EVENT_ENDTHREAD_DONE,
};

struct perf_helper_proxy_event {
    enum perf_helper_proxy_event_type type;
    pid_t thread_tid;
    int perf_event_fd;
    int bpf_map_fd;
};

void init_perf_helper_proxy(void);
#endif

