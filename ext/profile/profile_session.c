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

#include "profile.h"
#include "profile_session.h"
#include "stack_sample.bpf.h"

VALUE cProfileSession;


struct ProfileSession {
    VALUE perf_helper_proxy;

    VALUE event_loop_thread;
    rb_atomic_t event_loop_flags;
};

static void
profile_session_mark(void *ctx)
{
    struct ProfileSession *sess = ctx;
    rb_gc_mark_movable(sess->perf_helper_proxy);
    rb_gc_mark_movable(sess->event_loop_thread);
}

static void
profile_session_compact(void *ctx)
{
    struct ProfileSession *sess = ctx;
    sess->perf_helper_proxy = rb_gc_location(sess->perf_helper_proxy);
    sess->event_loop_thread = rb_gc_location(sess->event_loop_thread);
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

VALUE
new_profile_session(void)
{
    struct ProfileSession *sess;
    VALUE self = TypedData_Make_Struct(cProfileSession, struct ProfileSession,
                                       &profile_session_data_type, sess);

    sess->perf_helper_proxy = new_perf_helper_proxy();
    return self;
}

void
close_profile_session(VALUE self)
{
    struct ProfileSession *sess;
    TypedData_Get_Struct(self, struct ProfileSession,
                         &profile_session_data_type, sess);

    if (RB_TEST(sess->perf_helper_proxy)) {
        close_perf_helper_proxy(sess->perf_helper_proxy);
    } 
}

void init_profile_session(void)
{
    cProfileSession = rb_define_class_under(mProfile, "Session", rb_cObject);
    rb_undef_alloc_func(cProfileSession);
}
