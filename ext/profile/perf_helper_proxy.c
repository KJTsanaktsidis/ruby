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

VALUE cPerfHelperProxy;
static VALUE rb_cSocket;

static int
pidfd_send_signal(int pidfd, int sig, siginfo_t *info, unsigned int flags)
{
    return syscall(SYS_pidfd_send_signal, pidfd, sig, info, flags);
}

struct PerfHelperProxy {
    VALUE helper_pidfd;
    VALUE helper_socket;
    VALUE helper_stderr;
    pid_t helper_pid;
};

static void
perf_helper_proxy_mark(void *ctx)
{
    struct PerfHelperProxy *sess = ctx;
}

static void
perf_helper_proxy_compact(void *ctx)
{
    struct PerfHelperProxy *sess = ctx;
}

static void
perf_helper_proxy_free(void *ctx) {
    struct PerfHelperProxy *sess = ctx;
    ruby_xfree(sess);
}

static size_t
perf_helper_proxy_memsize(const void *ctx) {
    const struct PerfHelperProxy *sess = ctx;
    return sizeof(*sess);
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

static int
exec_helper_process(void *ctxptr)
{
    struct exec_helper_process_ctx *ctx = ctxptr;
    int n;
    char msgbuf[PIPE_BUF];
    char strerrbuf[128];
    if (dup2(ctx->stderr_fd, 2) == -1) {
        n = snprintf(msgbuf, PIPE_BUF, "failed to dup3 stderr_fd: %s\n",
                     strerror_r(errno, strerrbuf, sizeof(strerrbuf)));
        write(ctx->stderr_fd, msgbuf, n);
        exit(1);
    }
    if (dup2(ctx->socket_fd, 3) == -1) {
        n = snprintf(msgbuf, PIPE_BUF, "failed to dup3 socket_fd: %s\n",
                     strerror_r(errno, strerrbuf, sizeof(strerrbuf)));
        write(ctx->stderr_fd, msgbuf, n);
        exit(1);
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
    n = snprintf(msgbuf, PIPE_BUF, "failed to execve helper program: %s",
                 strerror_r(errno, strerrbuf, sizeof(strerrbuf)));
    write(ctx->stderr_fd, msgbuf, n);
    exit(1);
}


static void
fork_helper_process(const char *helper_path, struct PerfHelperProxy *proxy)
{
    /* Command socket we will communicate with the helper process on */
    VALUE sockets = rb_funcall(rb_cSocket, rb_intern("socketpair"), 2,
                               rb_const_get(rb_cSocket, rb_intern("AF_UNIX")),
                               rb_const_get(rb_cSocket, rb_intern("SOCK_SEQPACKET")));

    proxy->helper_socket = RARRAY_AREF(sockets, 0);
    VALUE helper_socket_remote = RARRAY_AREF(sockets, 1);

    /* The helper process will open this pipe as its stderr */
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
    int child_status;
    int r = waitpid(proxy->helper_pid, &child_status, WNOHANG | __WCLONE);
    if (r == -1) {
        rb_sys_fail("failed to waitpid(2) helper child");
    }
    if (r != 0) {
        /* means it _did_ exit */
        VALUE errmsg = rb_funcall(proxy->helper_stderr, rb_intern("read"), 0);
        rb_raise(rb_eRuntimeError, "failed to exec helper process: %"PRIsVALUE, errmsg);
    }

    RB_GC_GUARD(sockets);
    RB_GC_GUARD(pipes);
}

VALUE new_perf_helper_proxy(void)
{
    struct PerfHelperProxy *proxy;
    VALUE obj = TypedData_Make_Struct(cProfileSession, struct PerfHelperProxy,
                                      &perf_helper_proxy_data_type, proxy);
    proxy->helper_pid = 0;
    proxy->helper_pidfd = -1;
    proxy->helper_socket = -1;

    /* Find & fork the helper process */
    VALUE helper_path = find_helper_binary_path();
    fork_helper_process(StringValueCStr(helper_path), proxy);
    RB_GC_GUARD(helper_path);
    return obj;
}

void close_perf_helper_proxy(VALUE self)
{
    struct PerfHelperProxy *proxy;
    TypedData_Get_Struct(self, struct PerfHelperProxy,
                         &perf_helper_proxy_data_type, proxy);

    if (RB_TEST(proxy->helper_socket)) {
        rb_funcall(proxy->helper_socket, rb_intern("close"), 0);
        proxy->helper_socket = Qnil;
    }
    if (RB_TEST(proxy->helper_pidfd)) {
        int pidfd = RFILE(proxy->helper_pidfd)->fptr->fd;
        pidfd_send_signal(pidfd, SIGKILL, NULL, 0);
        rb_funcall(proxy->helper_pidfd, rb_intern("close"), 0);
        proxy->helper_pidfd = Qnil;
    }
    if (RB_TEST(proxy->helper_stderr)) {
        rb_funcall(proxy->helper_stderr, rb_intern("close"), 0);
        proxy->helper_stderr = Qnil;
    }
    if (proxy->helper_pid) {
        int r = waitpid(proxy->helper_pid, NULL, __WCLONE);
        if (r == -1) {
            rb_sys_fail("failed to waitpid(2) helper child");
        }
        proxy->helper_pid = 0;
    }
}

void init_perf_helper_proxy(void)
{
    rb_require("socket");
    rb_cSocket = rb_const_get(rb_cObject, rb_intern("Socket"));
    cProfileSession = rb_define_class_under(cProfile, "Session", rb_cObject);
    rb_undef_alloc_func(cProfileSession);
}
