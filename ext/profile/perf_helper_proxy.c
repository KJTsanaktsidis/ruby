#include "extconf.h"

#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
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

#include "perf_helper_message.h"
#include "profile.h"
#include "profile_session.h"
#include "perf_helper_proxy.h"
#include "stack_sample.bpf.h"

VALUE cPerfHelperProxy;
static VALUE rb_cSocket;

static int
pidfd_send_signal(int pidfd, int sig, siginfo_t *info, unsigned int flags)
{
    return syscall(SYS_pidfd_send_signal, pidfd, sig, info, flags);
}

/* Like ruby_xmalloc, but can be used outside GVL */
static void *
malloc_or_die(size_t n)
{
    void *r = malloc(n);
    if (!r) { abort(); }
    return r;
}

static void *
realloc_or_die(void *ptr, size_t sz)
{
    void *r = realloc(ptr, sz);
    if (!r) { abort(); }
    return r;
}

struct PerfHelperProxy {
    VALUE helper_pidfd;
    int helper_pidfd_fd;
    pid_t helper_pid;
    bool helper_exited;
    int helper_exit_status;

    VALUE helper_socket;
    int helper_socket_fd;

    VALUE helper_stderr;
    int helper_stderr_fd;
    char *stderr_buffer;
    size_t stderr_buffer_capa;
    size_t stderr_buffer_len;
};

static void
perf_helper_proxy_mark(void *ctx)
{
    struct PerfHelperProxy *proxy = ctx;
    rb_gc_mark_movable(proxy->helper_pidfd);
    rb_gc_mark_movable(proxy->helper_socket);
    rb_gc_mark_movable(proxy->helper_stderr);
}

static void
perf_helper_proxy_compact(void *ctx)
{
    struct PerfHelperProxy *proxy = ctx;
    proxy->helper_pidfd = rb_gc_location(proxy->helper_pidfd);
    proxy->helper_socket = rb_gc_location(proxy->helper_socket);
    proxy->helper_stderr = rb_gc_location(proxy->helper_stderr);
}

static void
perf_helper_proxy_free(void *ctx) {
    struct PerfHelperProxy *sess = ctx;
    ruby_xfree(sess);
}

static size_t
perf_helper_proxy_memsize(const void *ctx) {
    const struct PerfHelperProxy *proxy = ctx;
    return sizeof(*proxy);
}

static const rb_data_type_t perf_helper_proxy_data_type = {
    "Profile::PerfHelperProxy",
    {
        perf_helper_proxy_mark,
        perf_helper_proxy_free,
        perf_helper_proxy_memsize,
        perf_helper_proxy_compact
    },
    0, 0, 0
};

/* Finds the perf_helper binary - it should be in the same directory as the profile.so extension
 * library file */
static VALUE
find_helper_binary_path(void)
{
    Dl_info self_info;
    int r = dladdr(find_helper_binary_path, &self_info);
    if (r == 0) {
        rb_raise(rb_eRuntimeError, "profile.so extension does not appear to be dlopen()'d?");
    }

    /* This is a very long way of saying:
     * File.join(File.dirname(self_info.dli_fname), "perf_helper#{RbConfig::CONFIG['EXEEXT]}")
     * Maybe it would be better to just eval that? */
    VALUE so_path = rb_str_new_cstr(self_info.dli_fname);
    VALUE dirname = rb_funcall(rb_cFile, rb_intern("dirname"), 1, so_path);
    VALUE binname = rb_str_new_cstr("perf_helper");
    VALUE rbconfig = rb_const_get(rb_cObject, rb_intern("RbConfig"));
    VALUE exeext = rb_hash_aref(rb_const_get(rbconfig, rb_intern("CONFIG")),
                                rb_str_new_cstr("EXEEXT"));
    rb_str_append(binname, exeext);
    return rb_funcall(rb_cFile, rb_intern("join"), 2, dirname, "perf_helper");
}

/* Wraps IO::for_fd(fd, autoclose: true); used to create a ruby VALUE that takes
 * ownership of (and responsibility for closing & freeing) the specified FD. */
static VALUE
make_io_for_fd(int fd)
{
    VALUE for_fd_kwargs = rb_hash_new();
    rb_hash_aset(for_fd_kwargs, rb_intern("autoclose"), Qtrue);
    return rb_funcall(rb_cIO, rb_intern("for_fd"), 2, INT2NUM(fd), for_fd_kwargs);
}

struct exec_helper_process_ctx {
    int socket_fd;
    int stderr_fd;
    const char *helper_path;
    char stack[1024];
};

/* Called in the child process of clone() below. Sets up file descriptors and then
 * exec's the perf_helper binary */
static int
exec_helper_process(void *ctxptr)
{
    struct exec_helper_process_ctx *ctx = ctxptr;
    int n;
    char msgbuf[PIPE_BUF];
    char strerrbuf[128];

#define EXIT_WITH_MESSAGE(msg) do { \
    n = snprintf(msgbuf, PIPE_BUF, "%s: %s\n", msg, strerror_r(errno, strerrbuf, sizeof(strerrbuf))); \
    write(ctx->stderr_fd, msgbuf, n); \
    exit(1); } while (0)

    /* the pipe comes pre-CLOEXEC'd and also set to nonblocking; we need to undo
     * this */
    int stderr_fd_fl_flags = fcntl(ctx->stderr_fd, F_GETFL);
    if (stderr_fd_fl_flags == -1) {
        EXIT_WITH_MESSAGE("failed to call fcntl(2) F_GETFL for stderr_fd");
    }
    stderr_fd_fl_flags &= ~O_NONBLOCK;
    if (fcntl(ctx->stderr_fd, F_SETFL, stderr_fd_fl_flags) == -1) {
        EXIT_WITH_MESSAGE("failed to call fcntl(2) F_SETFL for stderr_fd");
    }
    int stderr_fd_fd_flags = fcntl(ctx->stderr_fd, F_GETFD);
    if (stderr_fd_fd_flags == -1) {
        EXIT_WITH_MESSAGE("failed to call fcntl(2) F_GETFD for stderr_fd");
    }
    stderr_fd_fd_flags &= ~FD_CLOEXEC;
    if (fcntl(ctx->stderr_fd, F_SETFD, stderr_fd_fd_flags) == -1) {
        EXIT_WITH_MESSAGE("failed to call fcntl(2) F_SETFD for stderr_fd");
    }
    if (dup2(ctx->stderr_fd, 2) == -1) {
        EXIT_WITH_MESSAGE("failed to call dup2(2) for stderr_fd");
    }

    /* the socketpair also comes wiht CLOEXEC  & NONBLOCK */
    int socket_fd_fl_flags = fcntl(ctx->socket_fd, F_GETFL);
    if (socket_fd_fl_flags == -1) {
        EXIT_WITH_MESSAGE("failed to call fcntl(2) F_GETFL for socket_fd");
    }
    socket_fd_fl_flags &= ~O_NONBLOCK;
    if (fcntl(ctx->socket_fd, F_SETFL, socket_fd_fl_flags) == -1) {
        EXIT_WITH_MESSAGE("failed to call fcntl(2) F_SETFL for socket_fd");
    }
    int socket_fd_fd_flags = fcntl(ctx->socket_fd, F_GETFD);
    if (socket_fd_fd_flags == -1) {
        EXIT_WITH_MESSAGE("failed to call fcntl(2) F_GETFD for socket_fd");
    }
    socket_fd_fd_flags &= ~FD_CLOEXEC;
    if (fcntl(ctx->socket_fd, F_SETFD, socket_fd_fd_flags) == -1) {
        EXIT_WITH_MESSAGE("failed to call fcntl(2) F_SETFD for socket_fd");
    }
    if (dup2(ctx->socket_fd, 3) == -1) {
        EXIT_WITH_MESSAGE("failed to call dup2(2) for socket_fd");
    }

    /* close all other FDs */
    close(0);
    close(1);
    close_range(4, ~0U, CLOSE_RANGE_UNSHARE);

    char *argv[2];
    /* it really is OK to just cast away the constness to the arguments for
     * execve */
    argv[0] = (char *)ctx->helper_path;
    argv[1] = NULL;
    char *envp[1];
    envp[0] = NULL;
    execve(ctx->helper_path, argv, envp);

    /* exec failed */
    EXIT_WITH_MESSAGE("failed to execve(2) helper program");
#undef EXIT_WITH_MESSAGE
}

/* Forks the privileged perf_helper binary, passing a pipe as stderr and a socketpair
 * as FD #3. After returning, the *proxy will have set:
 *   - its end of the stderr pipe (proxy->helper_stderr)
 *   - its end of the command socket (proxy->helper_socket)
 *   - a pidfd for the child (proxy->helper_pidfd)
 */
static void
fork_helper_process(const char *helper_path, struct PerfHelperProxy *proxy)
{
    /* Command socket we will communicate with the helper process on.
     * N.B. - ruby's socketpair implementation automatically marks sockets as SOCK_NONBLOCK
     * and SOCK_CLOEXEC. */
    VALUE sockets = rb_funcall(rb_cSocket, rb_intern("socketpair"), 2,
                               rb_const_get(rb_cSocket, rb_intern("AF_UNIX")),
                               rb_const_get(rb_cSocket, rb_intern("SOCK_SEQPACKET")));

    proxy->helper_socket = RARRAY_AREF(sockets, 0);
    VALUE helper_socket_remote = RARRAY_AREF(sockets, 1);

    /* The helper process will open this pipe as its stderr. Again, Ruby's pipe implementation
     * automatically marks the pipe as O_NONBLOCK and O_CLOEXEC. */
    VALUE pipes = rb_funcall(rb_cIO, rb_intern("pipe"), 0);
    proxy->helper_stderr = RARRAY_AREF(pipes, 0);
    VALUE helper_stderr_remote = RARRAY_AREF(pipes, 1);

    struct exec_helper_process_ctx exec_ctx;
    exec_ctx.socket_fd = RFILE(helper_socket_remote)->fptr->fd;
    exec_ctx.stderr_fd = RFILE(helper_stderr_remote)->fptr->fd;
    exec_ctx.helper_path = helper_path;
    int raw_pidfd;
    int pid = clone(exec_helper_process, &exec_ctx.stack,
                    /* Suspend this process until the child process is exec'd. This is actually
                     * needed because we're using a stack-allocated buffer here as the stack for
                     * the child process.
                     * Note that we're NOT using CLONE_VM, so unlike actual vfork(2), this doesn't
                     * result in the child sharing the same address space as us. It just means we
                     * block waiting for it. */
                    CLONE_VFORK |
                    /* We want a pidfd for the child */
                    CLONE_PIDFD,
                    /* We deliberately do NOT pass a signal as part of the flags here - we do
                     * NOT want to generate a SIGCHLD when the helper exits; that may intefere
                     * with any SIGCHLD management happening in the application. */
                    &exec_ctx, &raw_pidfd);
    if (pid == -1) {
        rb_sys_fail("failed to clone(2) helper process");
    }

    proxy->helper_pidfd = make_io_for_fd(raw_pidfd);
    proxy->helper_pid = pid;

    /* close our end of the pipes */
    rb_funcall(helper_socket_remote, rb_intern("close"), 0);
    rb_funcall(helper_stderr_remote, rb_intern("close"), 0);

    /* Check if the child exited (i.e. it did not exec successfully) */
    siginfo_t child_status;
    int r = waitid(P_PIDFD, proxy->helper_pidfd_fd, &child_status, WEXITED | WNOHANG | __WCLONE);
    if (r == -1) {
        rb_sys_fail("failed to waitid(2) helper child");
    }
    if (r != 0) {
        /* means it _did_ exit */
        VALUE errmsg = rb_funcall(proxy->helper_stderr, rb_intern("read"), 0);
        rb_raise(rb_eRuntimeError, "failed to exec helper process: %"PRIsVALUE, errmsg);
    }

    RB_GC_GUARD(sockets);
    RB_GC_GUARD(pipes);
}

/* Creates a new instance of Profile::PerfHelperProxy. This will cause the perf_helper
 * privileged binary to be forked & exec'd */
VALUE
perf_helper_proxy_new(void)
{
    struct PerfHelperProxy *proxy;
    VALUE self = TypedData_Make_Struct(cPerfHelperProxy, struct PerfHelperProxy,
                                       &perf_helper_proxy_data_type, proxy);

    proxy->helper_pidfd = Qnil;
    proxy->helper_pidfd_fd = -1;
    proxy->helper_pid = 0;
    proxy->helper_exited = false;
    proxy->helper_exit_status = 0;
    proxy->helper_socket = Qnil;
    proxy->helper_socket_fd = -1;
    proxy->helper_stderr = Qnil;
    proxy->helper_stderr_fd = -1;
    proxy->stderr_buffer_capa = PIPE_BUF;
    proxy->stderr_buffer_len = 0;
    proxy->stderr_buffer = malloc_or_die(proxy->stderr_buffer_capa);

    /* Find & fork the helper process */
    VALUE helper_path = find_helper_binary_path();
    fork_helper_process(StringValueCStr(helper_path), proxy);

    /* We keep copies of the numeric FDs so we can access them without the GVL */
    proxy->helper_pidfd_fd = RFILE(proxy->helper_pidfd)->fptr->fd;
    proxy->helper_socket_fd = RFILE(proxy->helper_socket)->fptr->fd;
    proxy->helper_stderr_fd = RFILE(proxy->helper_stderr)->fptr->fd;

    RB_GC_GUARD(helper_path);
    return self;
}

/* Frees resources associated with the perf_helper invocation. This will close all
 * the sockets, terminate the perf_helper child process, and ensure that is is reaped */
void
perf_helper_proxy_close(VALUE self)
{
    struct PerfHelperProxy *proxy;
    TypedData_Get_Struct(self, struct PerfHelperProxy,
                         &perf_helper_proxy_data_type, proxy);

    if (RB_TEST(proxy->helper_socket)) {
        rb_funcall(proxy->helper_socket, rb_intern("close"), 0);
        proxy->helper_socket = Qnil;
        proxy->helper_socket_fd = -1;
    }
    if (RB_TEST(proxy->helper_stderr)) {
        rb_funcall(proxy->helper_stderr, rb_intern("close"), 0);
        proxy->helper_stderr = Qnil;
        proxy->helper_stderr_fd = -1;
    }
    if (RB_TEST(proxy->helper_pidfd)) {
        if (!proxy->helper_exited) {
            pidfd_send_signal(proxy->helper_pidfd_fd, SIGKILL, NULL, 0);
            siginfo_t child_status;
            int r = waitid(P_PIDFD, proxy->helper_pidfd_fd, &child_status, WEXITED | __WCLONE);
            if (r == -1) {
                rb_sys_fail("failed to waitid(2) helper child");
            }
            proxy->helper_exited = true;
        }
        rb_funcall(proxy->helper_pidfd, rb_intern("close"), 0);
        proxy->helper_pidfd = Qnil;
        proxy->helper_pidfd_fd = -1;
    }
}

/* Reads from the stderr pipe into the internal proxy->stderr_buffer until there are no
 * more bytes available to read */
static int
poll_stderr(struct PerfHelperProxy *proxy, char *errbuf, size_t errbuf_len)
{
    char strerror_buf[256];
    while (true) {
        int n = read(proxy->helper_stderr_fd,
                     proxy->stderr_buffer + proxy->stderr_buffer_len,
                     proxy->stderr_buffer_capa - proxy->stderr_buffer_len);
        if (n == -1 && errno == EINTR) {
            continue;
        }
        if (n == -1 && errno == EWOULDBLOCK) {
            return 0;
        }
        if (n == -1) {
            snprintf(errbuf, errbuf_len, "error from read(2) of stderr pipe: %s",
                     strerror_r(errno, strerror_buf, sizeof(strerror_buf)));
            return -1;
        }
        if (n == 0) {
            /* EOF */
            return 1;
        }
        proxy->stderr_buffer_len += n;
        if (proxy->stderr_buffer_len >= proxy->stderr_buffer_capa) {
            proxy->stderr_buffer_capa *= 2;
            proxy->stderr_buffer = realloc_or_die(proxy->stderr_buffer, proxy->stderr_buffer_capa);
        }
    }
}

/* Reaps the perf_helper child process if it has exited */
static int
poll_reap_process(struct PerfHelperProxy *proxy, char *errbuf, size_t errbuf_len)
{
    char strerror_buf[256];
    siginfo_t child_status;

    if (proxy->helper_exited) {
        return 0;
    }
    int r = waitid(P_PIDFD, proxy->helper_pidfd_fd, &child_status, WEXITED | WNOHANG | __WCLONE);
    if (r == 0) {
        /* not exited yet */
        return 0;
    }
    if (r == -1) {
        snprintf(errbuf, errbuf_len, "error from waitid(2) of helper process: %s",
                 strerror_r(errno, strerror_buf, sizeof(strerror_buf)));
        return -1;
    }
    proxy->helper_exited = true;
    proxy->helper_exit_status = child_status.si_status;
    return 1;
}

/* Receives any pending response from the socket shared with the perf_helper binary */
static int
poll_message_socket(struct PerfHelperProxy *proxy, char *errbuf, size_t errbuf_len)
{
    return 0;
}

/* Polls for any events from the perf_helper child process. This is:
 *   - A response from one of the commands we sent over the socket
 *   - That's actually all it can be for nw.
 * If the perf_helper child process has exited, then this fact is communicated
 * as a return value of -1 & the message is written into the errbuf provided.
 *
 * This should be called when one of the FDs from perf_helper_proxy_get_poll_fds
 * is readable or writeable */
int
pref_helper_proxy_poll_event(struct PerfHelperProxy *proxy,
                             struct perf_helper_proxy_event *event_out,
                               char *errbuf, size_t errbuf_len)
{
    int did_reap = poll_reap_process(proxy, errbuf, errbuf_len);
    if (did_reap == -1) {
        return -1;
    }

    int r = poll_stderr(proxy, errbuf, errbuf_len);
    if (r == -1) {
        return -1;
    }

    if (did_reap) {
        /* just treat "the helper process exited" as an error */
        snprintf(errbuf, errbuf_len, "perf_helper process exited with status %d: %.*s",
                 proxy->helper_exit_status, (int)proxy->stderr_buffer_len, proxy->stderr_buffer);
        return -1;
    }

    return 0;
}

void init_perf_helper_proxy(void)
{
    rb_require("socket");
    rb_cSocket = rb_const_get(rb_cObject, rb_intern("Socket"));
    cProfileSession = rb_define_class_under(cProfile, "Session", rb_cObject);
    rb_undef_alloc_func(cProfileSession);
}
