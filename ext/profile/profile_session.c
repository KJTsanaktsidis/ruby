#include "extconf.h"

#include <ruby.h>
#include <ruby/atomic.h>

#include "perf_helper.h"
#include "profile.h"
#include "profile_session.h"
#include "stack_sample.bpf.h"

struct ProfileSession {
};

static void
profile_session_mark(void *ctx)
{
    struct ProfileSession *sess = ctx;
}

static void
profile_session_compact(void *ctx)
{
    struct ProfileSession *sess = ctx;
}

static void
profile_session_free(void *ctx) {
    struct ProfileSession *sess = ctx;
    ruby_xfree(state);
}

static size_t
profile_session_memsize(const void *ctx) {
    const struct ProfileSession *sess = ctx;
    return sizeof(*sess);
}

static const rb_data_type_t native_profile_thread_state_type = {
    "native_profile_thread_state",
    {
        native_profile_thread_state_mark,
        native_profile_thread_state_free,
        native_profile_thread_state_memsize,
        native_profile_thread_state_compact
    },
    0, 0, 0
};
