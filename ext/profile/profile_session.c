#include "extconf.h"

#include <dlfcn.h>
#include <errno.h>
#include <linux/close_range.h>
#include <ruby.h>
#include <ruby/atomic.h>
#include <ruby/io.h>
#include <sched.h>
#include <sys/signal.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/wait.h>

#include "perf_helper.h"
#include "profile.h"
#include "profile_session.h"
#include "ruby/internal/intern/gc.h"
#include "stack_sample.bpf.h"

VALUE cProfileSession;


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
    ruby_xfree(sess);
}

static size_t
profile_session_memsize(const void *ctx) {
    const struct ProfileSession *sess = ctx;
    return sizeof(*sess);
}

static const rb_data_type_t profile_session_data_type = {
    "Profile::Session",
    {
        profile_session_mark,
        profile_session_free,
        profile_session_memsize,
        profile_session_compact
    },
    0, 0, 0
};


void init_profile_session(void)
{
    cProfileSession = rb_define_class_under(cProfile, "Session", rb_cObject);
    rb_undef_alloc_func(cProfileSession);
}
