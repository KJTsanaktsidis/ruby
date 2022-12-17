#include "extconf.h"

#include <bpf/libbpf.h>
#include <poll.h>
#include <linux/perf_event.h>
#include <linux/types.h>
#include <ruby.h>
#include <ruby/atomic.h>
#include <ruby/io.h>
#include <ruby/thread.h>
#include <stdlib.h>
#include <sys/ioctl.h>

#include "vm_core.h"

#include "perf_helper.h"
#include "profile.h"
#include "stack_sample.bpf.h"

VALUE rb_cProfile;
VALUE rb_cProfileState;

struct native_profile_thread_state {
    /* protected by GVL */
    VALUE perf_io;
    VALUE ringbuf_io;
    VALUE link_io;
    VALUE prog_io;
    VALUE wakepipe_read_io;
    VALUE wakepipe_write_io;

    /* not protected by gvl */
    int perf_fd;
    int ringbuf_fd;
    int wakepipe_read_fd;
    int wakepipe_write_fd;
    rb_atomic_t wake_flag;
    struct ring_buffer *ringbuf;

    int ret;
    char errbuf[256];
};

static void
native_profile_thread_state_mark(void *ctx)
{
    struct native_profile_thread_state *state = ctx;
    rb_gc_mark_movable(state->perf_io);
    rb_gc_mark_movable(state->ringbuf_io);
    rb_gc_mark_movable(state->link_io);
    rb_gc_mark_movable(state->prog_io);
    rb_gc_mark_movable(state->wakepipe_read_io);
    rb_gc_mark_movable(state->wakepipe_write_io);
}

static void
native_profile_thread_state_compact(void *ctx)
{
    struct native_profile_thread_state *state = ctx;
    state->perf_io = rb_gc_location(state->perf_io);
    state->ringbuf_io = rb_gc_location(state->ringbuf_io);
    state->link_io = rb_gc_location(state->link_io);
    state->prog_io = rb_gc_location(state->prog_io);
    state->wakepipe_read_io = rb_gc_location(state->wakepipe_read_io);
    state->wakepipe_write_io = rb_gc_location(state->wakepipe_write_io);
}

static void
native_profile_thread_state_free(void *ctx) {
    struct native_profile_thread_state *state = ctx;
    ruby_xfree(state);
}

static size_t
native_profile_thread_state_memsize(const void *ctx) {
    const struct native_profile_thread_state *state = ctx;
    return sizeof(*state);
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


static void *
native_profile_thread_nogvl(void *ctx)
{
    struct native_profile_thread_state *state = ctx;
    int r;

    r = ioctl(state->perf_fd, PERF_EVENT_IOC_ENABLE, 0);
    if (r == -1) {
        snprintf(state->errbuf, sizeof(state->errbuf), "error on ioctl(PERF_EVENT_IOC_ENABLE): %d", errno);
        state->ret = -1;
        return NULL;
    }

    struct pollfd pollfds[2];
    pollfds[0].fd = ring_buffer__epoll_fd(state->ringbuf);
    pollfds[0].events = POLLIN;
    pollfds[1].fd = state->wakepipe_read_fd;
    pollfds[1].events = POLLIN;

    while (true) {
        pollfds[0].revents = 0;
        pollfds[1].revents = 0;

        rb_atomic_t wake_flag_val = RUBY_ATOMIC_FETCH_ADD(state->wake_flag, 0);
        if (wake_flag_val > 0) {
            state->ret = 0;
            return NULL;
        }

        r = poll(pollfds, 2, -1);
        if (r == -1 && errno == EAGAIN) {
            continue;
        }
        if (r == 0) {
            continue;
        }
        if (r == -1) {
            snprintf(state->errbuf, sizeof(state->errbuf), "error on poll(2): %d", errno);
            state->ret = -1;
            return NULL;
        }

        if (pollfds[0].revents & POLLIN) {
            r = ring_buffer__poll(state->ringbuf, 0);
            if (r == -1 && errno != EAGAIN) {
                snprintf(state->errbuf, sizeof(state->errbuf), "error on ring_buffer__poll(): %d", errno);
                state->ret = -1;
                return NULL;
            }
        }
        if (pollfds[1].revents & POLLIN) {
            char discard_buf[PIPE_BUF];
            r = read(state->wakepipe_read_fd, discard_buf, sizeof(discard_buf));
            if (r == -1 && errno != EAGAIN) {
                snprintf(state->errbuf, sizeof(state->errbuf), "error on read(2) for wake pipe: %d", errno);
                state->ret = -1;
                return NULL;
            }
        }
    }
}

static void
native_profile_thread_ubf(void *ctx)
{
    struct native_profile_thread_state *state = ctx;
    RUBY_ATOMIC_ADD(state->wake_flag, 1);
    char wbuf[1] = { '\0' };
    write(state->wakepipe_write_fd, wbuf, 1);
}

static VALUE
native_profile_thread_runloop(void *ctx)
{
    VALUE state_wrapper = rb_ivar_get(rb_cProfile, rb_intern("profile_state"));
    struct native_profile_thread_state *state;
    TypedData_Get_Struct(state_wrapper, struct native_profile_thread_state,
                         &native_profile_thread_state_type, state);

    rb_thread_call_without_gvl(native_profile_thread_nogvl, state, native_profile_thread_ubf, &state);
    if (state->ret == -1) {
        rb_raise(rb_eStandardError, "error from native profile thread: %s", state->errbuf);
    }
    return Qnil;
}


static int
ringbuf_event_handler(void *ctx, void *data, size_t size)
{
    struct stack_sample_entry *entry = data;
    fprintf(stderr, "an event: pid %u, sample %llu\n", entry->pid, entry->sample_period);
    return 0;
}

static VALUE
profile_s_start(VALUE klass)
{
    struct native_profile_thread_state *state;
    VALUE state_wrapper = TypedData_Make_Struct(rb_cProfileState, struct native_profile_thread_state,
                                                &native_profile_thread_state_type, state);
    rb_ivar_set(klass, rb_intern("profile_state"), state_wrapper);

    struct perf_helper_input req = {
        .ruby_current_vm_ptr = (uintptr_t)GET_VM(),
    };
    VALUE req_string = rb_str_new((char *)&req, sizeof(struct perf_helper_input));
    VALUE helper_fds = rb_funcall(klass, rb_intern("_get_fds_from_helper"), 1, req_string);

    state->perf_io = RARRAY_AREF(helper_fds, 0);
    Check_Type(state->perf_io, T_FILE);
    state->ringbuf_io = RARRAY_AREF(helper_fds, 1);
    Check_Type(state->ringbuf_io, T_FILE);
    state->link_io = RARRAY_AREF(helper_fds, 2);
    Check_Type(state->link_io, T_FILE);
    state->prog_io = RARRAY_AREF(helper_fds, 3);
    Check_Type(state->prog_io, T_FILE);

    state->perf_fd = RFILE(state->perf_io)->fptr->fd;
    state->ringbuf_fd = RFILE(state->ringbuf_io)->fptr->fd;
    state->ringbuf = ring_buffer__new(state->ringbuf_fd, ringbuf_event_handler, &state, NULL);
    if (!state->ringbuf) {
        rb_sys_fail("libbpf ring_buffer__new() failed");
    }
    VALUE wakepipes = rb_funcall(rb_cIO, rb_intern("pipe"), 0);
    state->wakepipe_read_io = RARRAY_AREF(wakepipes, 0);
    Check_Type(state->wakepipe_read_io, T_FILE);
    state->wakepipe_write_io = RARRAY_AREF(wakepipes, 1);
    Check_Type(state->wakepipe_write_io, T_FILE);
    state->wakepipe_read_fd = RFILE(state->wakepipe_read_io)->fptr->fd;
    state->wakepipe_write_fd = RFILE(state->wakepipe_write_io)->fptr->fd;
    rb_funcall(state->wakepipe_read_io, rb_intern("nonblock="), 1, Qtrue);
    rb_funcall(state->wakepipe_write_io, rb_intern("nonblock="), 1, Qtrue);

    RUBY_ATOMIC_SET(state->wake_flag, 0);
    state->ret = 0;
    memset(state->errbuf, 0, sizeof(state->errbuf));

    VALUE profile_thread = rb_thread_create(native_profile_thread_runloop, NULL);
    rb_ivar_set(klass, rb_intern("profile_thread"), profile_thread);
    return Qnil;
}

static VALUE
profile_s_stop(VALUE klass)
{
    VALUE state_wrapper = rb_ivar_get(klass, rb_intern("profile_state"));
    struct native_profile_thread_state *state;
    TypedData_Get_Struct(state_wrapper, struct native_profile_thread_state,
                         &native_profile_thread_state_type, state);
    RUBY_ATOMIC_ADD(state->wake_flag, 1);
    char wbuf[1] = { '\0' };
    write(state->wakepipe_write_fd, wbuf, 1);

    VALUE profile_thread = rb_ivar_get(klass, rb_intern("profile_thread"));
    rb_funcall(profile_thread, rb_intern("join"), 0);
    return Qnil;
}


void
Init_profile(void)
{
    rb_cProfile = rb_define_class_under(rb_cObject, "Profile", rb_cObject);
    rb_undef_alloc_func(rb_cProfile);
    rb_cProfileState = rb_define_class_under(rb_cProfile, "State", rb_cObject);
    rb_undef_alloc_func(rb_cProfileState);

    rb_define_singleton_method(rb_cProfile, "start",
                               profile_s_start, 0);
    rb_define_singleton_method(rb_cProfile, "stop",
                               profile_s_stop, 0);
}
