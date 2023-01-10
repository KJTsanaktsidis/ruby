#include "extconf.h"

#include <errno.h>
#include <fcntl.h>
#include <linux/close_range.h>
#include <pthread.h>
#include <ruby.h>
#include <ruby/io.h>
#include <sched.h>
#include <signal.h>
#include <stdbool.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#include "profile.h"
#include "linux.h"

VALUE mProfileLinux;

/* Need to copy a couple macro definitions out of glibc to make it possible
 * to call these rt_* functions correctly. The kernel expects setsize to be
 *  sizeof(sigset_t), where sigset_t is the _KERNEL_ version of that type.
 * In the kernel, sigset_t is 8 bytes. However, in glibc headers, sigset_t
 * is actually some enormous 128 byte structure.
 * Do the same maths as glibc to get the right value to pass to the kernel.\
 */

#define ALIGN_DOWN(base, size)  ((base) & -((__typeof__ (base)) (size)))
#define ALIGN_UP(base, size)    ALIGN_DOWN ((base) + (size) - 1, (size))
#define __NSIG_WORDS (ALIGN_UP ((_NSIG - 1), ULONG_WIDTH) / ULONG_WIDTH)
#define __NSIG_BYTES (__NSIG_WORDS * (ULONG_WIDTH / UCHAR_WIDTH))

/* glibc versions of sigaddset & sigfillset implicitly ignore attempts to set
 * the glibc protected internal signals we need to mask. Copy some more internal
 * macros.
 */
#define __sigset_t unsigned long int
#define __sigmask(sig) (((__sigset_t) 1) << ((sig) - 1))
#define __sigaddset(set, sig)                   \
  (__extension__ ({                             \
    __sigset_t __mask = __sigmask (sig);        \
    *(set) |= __mask;                           \
    0;                                          \
  }))

static int
rt_sigprocmask(int how, const sigset_t *set, sigset_t *oldset, size_t setsize)
{
    return syscall(SYS_rt_sigprocmask, how, set, oldset, setsize);
}

static int
rt_sigaction(int signum, const struct sigaction *act, struct sigaction *oldact, size_t setsize)
{
    return syscall(SYS_rt_sigaction, signum, act, oldact, setsize);
}

static int
pidfd_send_signal(int pidfd, int sig, siginfo_t *info, unsigned int flags)
{
    return syscall(SYS_pidfd_send_signal, pidfd, sig, info, flags);
}

struct spawn_context_fd_redirection {
    int fd_from;
    int fd_to;
    int fd_tmp;
};

/* glibc uses a 32k stack in its implementation of posix_spawn, so... guess we just go with that? */
#define SPAWN_STACK_SIZE (32 * 1024)
struct spawn_context {
    int cmdline_arg_count;
    char **cmdline;
    size_t cmdline_byte_len;

    int fd_redirection_count;
    VALUE fd_redirections_rb;
    struct spawn_context_fd_redirection *fd_redirections;
    VALUE dev_null;

    void *stack;

    sigset_t full_sigset;
    sigset_t old_sigset;
    bool did_mask_signals;
    int old_pthread_cancel_state;
    bool did_set_cancel_state;

    bool have_child_error;
    char child_error[256];
};

static void spawn_context_mark(void *obj) {
    struct spawn_context *ctx = obj;
    rb_gc_mark_movable(ctx->fd_redirections_rb);
    rb_gc_mark_movable(ctx->dev_null);
}
static void spawn_context_compact(void *obj) {
    struct spawn_context *ctx = obj;
    ctx->fd_redirections_rb = rb_gc_location(ctx->fd_redirections_rb);
    ctx->dev_null = rb_gc_location(ctx->dev_null);
}

static void
spawn_context_free(void *obj) {
    struct spawn_context *ctx = obj;

    if (ctx->cmdline) {
        for (int i = 0; i < ctx->cmdline_arg_count; i++) {
            if (ctx->cmdline[i]) {
                ruby_xfree(ctx->cmdline[i]);
            }
        }
    }
    if (ctx->fd_redirections) {
        ruby_xfree(ctx->fd_redirections);
    }
    if (ctx->stack && ctx->stack != MAP_FAILED) {
        munmap(ctx->stack, SPAWN_STACK_SIZE);
    }
}

static size_t
spawn_context_memsize(const void *obj)
{
    const struct spawn_context *ctx = obj;
    size_t sz = sizeof(struct spawn_context);
    sz += ctx->cmdline_byte_len;
    sz += (ctx->fd_redirection_count * sizeof(struct spawn_context_fd_redirection));
    if (ctx->stack) {
        sz += SPAWN_STACK_SIZE;
    }
    return sz;
}

static const rb_data_type_t spawn_context_data_type = {
    "Profile::Linux::spawn_context",
    {
        spawn_context_mark,
        spawn_context_free,
        spawn_context_memsize,
        spawn_context_compact
    },
    0, 0, 0
};

static int
foreach_spawn_option(VALUE key, VALUE val, VALUE ctxarg)
{
    struct spawn_context *ctx;
    TypedData_Get_Struct(ctxarg, struct spawn_context, &spawn_context_data_type, ctx);

    /* We support "some" of the options that Process.spawn has (i.e. the ones I need).*/
    if (rb_obj_is_kind_of(key, rb_cInteger)) {
        VALUE rb_redir = rb_ary_resize(rb_ary_new(), 2);
        RARRAY_ASET(rb_redir, 0, key);
        RARRAY_ASET(rb_redir, 1, val);
        rb_ary_push(ctx->fd_redirections_rb, rb_redir);
        return ST_CONTINUE;
    }
    /* Don't know how to handle this one. */
    rb_raise(rb_eNotImpError, "spawn option %"PRIsVALUE" -> %"PRIsVALUE" not implemented",
             key, val);
}

static int
prepare_thread_for_clone(struct spawn_context *ctx, char *errbuf, size_t errbuf_len)
{
    int r;
    char strerror_buf[256];

    r = pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, &ctx->old_pthread_cancel_state);
    if (r != 0) {
        snprintf(errbuf, errbuf_len, "pthread_setcancelstate(3) failed during prepare: %s",
                 strerror_r(r, strerror_buf, sizeof(strerror_buf)));
        return -1;
    }
    ctx->did_set_cancel_state = true;

    sigfillset(&ctx->full_sigset);
    /* glibc otherwise refuses to set these */
    __sigaddset((__sigset_t *)&ctx->full_sigset, __SIGRTMIN);
    __sigaddset((__sigset_t *)&ctx->full_sigset, __SIGRTMIN+1);
    /* The glibc pthread_sigmask/sigprocmask wrappers transparently reject attempts
     * to mask signals used internally by glibc's thread implementation, but we need
     * to do that in this case. So, call the raw rt_sigprocmask syscall. */
    r = rt_sigprocmask(SIG_SETMASK, &ctx->full_sigset, &ctx->old_sigset, __NSIG_BYTES);
    if (r != 0) {
        snprintf(errbuf, errbuf_len, "rt_sigprocmask(2) failed during prepare: %s",
                 strerror_r(errno, strerror_buf, sizeof(strerror_buf)));
        return -1;
    }
    ctx->did_mask_signals = true;

    return 0;
}

static int
restore_thread_after_clone(struct spawn_context *ctx, char *errbuf, size_t errbuf_len)
{
    int r;
    int ret = 0;
    char strerror_buf[256];

    if (ctx->did_mask_signals) {
        r = rt_sigprocmask(SIG_SETMASK, &ctx->old_sigset, NULL, __NSIG_BYTES);
        if (r != 0) {
            snprintf(errbuf, errbuf_len, "rt_sigprocmask(2) failed during restore: %s",
                     strerror_r(errno, strerror_buf, sizeof(strerror_buf)));
            ret = -1;
        }
    }
    if (ctx->did_set_cancel_state) {
        r = pthread_setcancelstate(ctx->old_pthread_cancel_state, NULL);
        if (r != 0) {
            snprintf(errbuf, errbuf_len, "pthread_setcancelstate(3) failed during restore: %s",
                     strerror_r(r, strerror_buf, sizeof(strerror_buf)));
            ret = -1;
        }
    }

    return ret;
}

static int
spawn_child_func(void *ctxarg)
{
    struct spawn_context *ctx = ctxarg;
    char strerror_buf[128];
    int r;

    /* We need to unset all the signal handlers back to defaults, so they don't actually execute
     * in our CLONE_VM shared memory if we get a signal. We have all the signals blocked, but
     * we can't keep the blocked before we exec, since that gets inherited.
     * This loop is mostly copying the logic from glibc's posix_spawn implementation, see
     * here: https://sourceware.org/git/?p=glibc.git;a=blob;f=sysdeps/unix/sysv/linux/spawni.c;hb=ae612c45efb5e34713859a5facf92368307efb6e
     * and fused with some of the patterns from disable_child_handler_fork_child in process.c.
     *
     * This is inefficiently calling rt_sigaction 128 times - CLONE_CLEAR_SIGHAND would
     * remove the need for this, but as I mention in profile_linux_s_spawn_private, we can't
     * use that for want of a glibc wrapper function */
    for (int sig = 1; sig < NSIG; sig++) {
        struct sigaction action;
        int r = rt_sigaction(sig, NULL, &action, __NSIG_BYTES);
        if (r == -1 && errno == EINVAL) {
            /* not actually a valid signal number*/
            continue;
        }
        if (r == -1) {
            /* I don't think this can actually happen. */
            snprintf(ctx->child_error, sizeof(ctx->child_error),
                     "failed to get signal disposition in child with rt_sigaction(2)");
            ctx->have_child_error = 1;
            return 1;
        }

        /* The two internal glibc signals _must_ be set to be ignored, don't want
         * the glibc handler for them poking around in this process. They'll be set
         * correctly after exec. */
        if (sig == __SIGRTMIN || sig == __SIGRTMIN + 1) {
            /* n.b. - __SIGRTMIN is the kernel one, i.e. 32, whilst SIGRTMIN is 34 (because
             * glibc addds +2 to it so it can use signals 32 & 33 for itself) */
            action.sa_handler = SIG_IGN;
        } else if (action.sa_handler == SIG_IGN || action.sa_handler == SIG_DFL) {
            /* Already in an OK state */
            continue;
        }

        r = rt_sigaction(sig, &action, NULL, __NSIG_BYTES);
        if (r == -1) {
            snprintf(ctx->child_error, sizeof(ctx->child_error),
                     "failed to set signal disposition in child with rt_sigaction(2): %s",
                     strerror_r(errno, strerror_buf, sizeof(strerror_buf)));
            ctx->have_child_error = true;
            return 1;
        }
    }

    /* Deal with file actions. In general, there could be cyclic dependencies amongst
     * FD numbers redirecting to each other. There's a bunch of nonsense in process.c
     * to untangle that (run_exec_dup2). I'm instead going to do something simple and
     * stupid, which is to dup all FDs to a new, temporary number, then dup them again
     * to the desired number, and hope we don't run out of FDs in the meanwhile. */
    for (int i = 0; i < ctx->fd_redirection_count; i++) {
        struct spawn_context_fd_redirection *redir = &ctx->fd_redirections[i];
        int newfd = dup(redir->fd_from);
        if (newfd == -1) {
            snprintf(ctx->child_error, sizeof(ctx->child_error),
                     "failed to dup(2) fd in child: %s",
                     strerror_r(errno, strerror_buf, sizeof(strerror_buf)));
            ctx->have_child_error = true;
            return 1;
        }
        redir->fd_tmp = newfd;
    }

    int highest_fd_to_keep = 0;
    for (int i = 0; i < ctx->fd_redirection_count; i++) {
        struct spawn_context_fd_redirection *redir = &ctx->fd_redirections[i];
        r = dup2(redir->fd_tmp, redir->fd_to);
        if (r == -1) {
            snprintf(ctx->child_error, sizeof(ctx->child_error),
                     "failed to dup2(2) fd in child: %s",
                     strerror_r(errno, strerror_buf, sizeof(strerror_buf)));
            ctx->have_child_error = true;
            return 1;
        }
        close(redir->fd_tmp);
        if (highest_fd_to_keep < redir->fd_to) {
            highest_fd_to_keep = redir->fd_to;
        }

        /* Make sure the CLOEXEC bit is unset on this fd. */
        int fd_flags = fcntl(redir->fd_to, F_GETFD);
        if (fd_flags == -1) {
            snprintf(ctx->child_error, sizeof(ctx->child_error),
                     "failed to call fcntl(2) F_GETFD in child: %s",
                     strerror_r(errno, strerror_buf, sizeof(strerror_buf)));
            ctx->have_child_error = true;
            return 1;
        }
        fd_flags &= ~FD_CLOEXEC;
        if (fcntl(redir->fd_to, F_SETFD, fd_flags) == -1) {
            snprintf(ctx->child_error, sizeof(ctx->child_error),
                     "failed to call fcntl(2) F_SETFD in child: %s",
                     strerror_r(errno, strerror_buf, sizeof(strerror_buf)));
            ctx->have_child_error = true;
            return 1;
        }
    }

    /* close everything else with this very inefficient loop */
    for (int i = 0; i < highest_fd_to_keep; i++) {
        bool should_keep = false;
        for (int j = 0; j < ctx->fd_redirection_count; j++) {
            if (ctx->fd_redirections[j].fd_to == j) {
                should_keep = true;
                break;
            }
        }
        if (!should_keep) {
            close(i);
        }
    }
    close_range(highest_fd_to_keep + 1, ~0U, 0);

    /* Unmask all the signals now, else the mask is preseved across execve */
    sigset_t empty_set;
    sigemptyset(&empty_set);
    r = rt_sigprocmask(SIG_SETMASK, &empty_set, NULL, __NSIG_BYTES);
    if (r == -1) {
        snprintf(ctx->child_error, sizeof(ctx->child_error),
                 "failed to unmask signals in child with rt_sigprocmask(2): %s",
                 strerror_r(errno, strerror_buf, sizeof(strerror_buf)));
        ctx->have_child_error = true;
        return 1;
    }

    char *empty_env[1] = { NULL };
    execve(ctx->cmdline[0], ctx->cmdline, empty_env);

    /* only reach here on error */
    snprintf(ctx->child_error, sizeof(ctx->child_error),
             "failed to execve(2) child program: %s",
             strerror_r(errno, strerror_buf, sizeof(strerror_buf)));
    ctx->have_child_error = true;
    return 1;
}

static void
copy_cmdline_to_cmem(struct spawn_context *ctx, VALUE cmdline)
{
    int nargs = RARRAY_LEN(cmdline);
    ctx->cmdline_arg_count = nargs;
    ctx->cmdline = ruby_xcalloc(nargs + 1, sizeof(char *));
    ctx->cmdline_byte_len += (nargs + 1) * sizeof(char *);
    for (int i = 0; i < nargs; i++) {
        VALUE str = RARRAY_AREF(cmdline, i);
        /* calloc ensures we have a null-terminator */
        ctx->cmdline[i] = ruby_xcalloc(RSTRING_LEN(str) + 1, 1);
        memcpy(ctx->cmdline[i], RSTRING_PTR(str), RSTRING_LEN(str));
        ctx->cmdline_byte_len += RSTRING_LEN(str) + 1;
    }
    ctx->cmdline[nargs] = NULL;
}

static void
copy_fd_redirections_to_cmem(struct spawn_context *ctx)
{
    ctx->fd_redirection_count = RARRAY_LEN(ctx->fd_redirections_rb);
    if (ctx->fd_redirection_count == 0) {
        return;
    }

    ctx->fd_redirections = ruby_xcalloc(ctx->fd_redirection_count,
                                        sizeof(struct spawn_context_fd_redirection));
    for (int i = 0; i < ctx->fd_redirection_count; i++) {
        VALUE rb_redir = RARRAY_AREF(ctx->fd_redirections_rb, i);
        VALUE rb_fd_from = RARRAY_AREF(rb_redir, 1);
        VALUE rb_fd_to = RARRAY_AREF(rb_redir, 0);

        int fd_to = RB_NUM2INT(rb_fd_to);
        int fd_from = -1;
        if (rb_obj_is_kind_of(rb_fd_from, rb_cIO)) {
            fd_from = RB_NUM2INT(rb_funcall(rb_fd_from, rb_intern("fileno"), 0));
        } else if (rb_obj_is_kind_of(rb_fd_from, rb_cInteger)) {
            fd_from = RB_NUM2INT(rb_fd_from);
        } else {
            rb_raise(rb_eTypeError, "don't know how to get FD from %"PRIsVALUE, rb_fd_from);
        }

        ctx->fd_redirections[i].fd_from = fd_from;
        ctx->fd_redirections[i].fd_to = fd_to;
        ctx->fd_redirections[i].fd_tmp = -1;
    }
}

/* Ensures fd's 0, 1, and 2 point to /dev/null if they don't point elsewhere. */
static void
ensure_stdio_mapped(struct spawn_context *ctx)
{
    for (int i = 0; i <= 2; i++) {
        bool mapped_descriptor = false;
        for (int j = 0; j < RARRAY_LEN(ctx->fd_redirections_rb); j++) {
            VALUE rb_redir = RARRAY_AREF(ctx->fd_redirections_rb, j);
            if (RB_NUM2INT(RARRAY_AREF(rb_redir, 0)) == i) {
                mapped_descriptor = true;
                break;
            }
        }
        if (mapped_descriptor) {
            continue;
        }
        if (!RB_TEST(ctx->dev_null)) {
            ctx->dev_null = rb_file_open("/dev/null", "r+");
        }
        VALUE ent = rb_ary_resize(rb_ary_new(), 2);
        RARRAY_ASET(ent, 1, ctx->dev_null);
        RARRAY_ASET(ent, 0, i);
        rb_ary_push(ctx->fd_redirections_rb, ent);
    }
}


static VALUE
profile_linux_s_spawn_private(VALUE klass, VALUE cmdline, VALUE options)
{
    char errbuf[256];
    char strerror_buf[128];
    bool raising_error = false;

    /* We need a wrapper struct to pass arguments to our child process function. That wrapper func will
     * be holding onto a reference to a bunch of malloc'd C memory (we need to copy the ruby stuff into it
     * before we fork). Use a Ruby wrapper object to hold it, so that the free func guarantees the wrapper
     * is freed in all code paths. */
    struct spawn_context *ctx;
    VALUE spawn_context_wrapper = TypedData_Make_Struct(rb_cObject, struct spawn_context, &spawn_context_data_type, ctx);
    ctx->fd_redirections_rb = rb_ary_new();

    if (RB_TEST(options)) {
        rb_hash_foreach(options, foreach_spawn_option, spawn_context_wrapper);
    }

    copy_cmdline_to_cmem(ctx, cmdline);
    ensure_stdio_mapped(ctx);
    copy_fd_redirections_to_cmem(ctx);


    ctx->stack = mmap(NULL, SPAWN_STACK_SIZE, PROT_READ | PROT_WRITE,
                      MAP_PRIVATE | MAP_ANONYMOUS | MAP_STACK, -1, 0);
    if (ctx->stack == MAP_FAILED) {
        rb_sys_fail("mmap(2) failed to allocate spawn child stack");
    }

    int r;
    r = prepare_thread_for_clone(ctx, errbuf, sizeof(errbuf));
    if (r == -1) {
        rb_raise(rb_eRuntimeError, "%s", errbuf);
    }

#if defined(PROFILE_STACK_GROWS_UP)
    void *stack_ptr = ctx->stack;
#elif defined(PROFILE_STACK_GROWS_DOWN)
    void *stack_ptr = (void *)(((uintptr_t)ctx->stack) + SPAWN_STACK_SIZE);
#endif

    int pidfd;
    pid_t pid = clone(spawn_child_func, stack_ptr,
                      /* Suspend this process until the child process is exec'd. */
                      CLONE_VFORK |
                      /* Share memory with the parent (because it's going to exec shortly afterwards).
                       * The combination of CLONE_VFORK and CLONE_VM is essentially vfork(2). */
                      CLONE_VM |
                      /* I _want_ to use CLONE_CLEAR_SIGHAND, but it can't be used with the clone
                       * syscall, only the clone3 syscall. As it is, we have to simulate its effects
                       * by masking all signals before the clone, then unsetting all the signal
                       * handlers in the child.
                       * We can't use clone3 because glibc doesn't have a wrapper function for it, which
                       * wouldn't ordinarily stop me but using the syscall requires some arch-specific
                       * asm trampoline to set up the new thread, and I don't really want to do that. */
                      /* CLONE_CLEAR_SIGHAND | */
                      /* We want a pidfd for the child */
                      CLONE_PIDFD,
                      /* We deliberately do NOT pass a signal as part of the flags here - we do
                       * NOT want to generate a SIGCHLD when the helper exits; that may intefere
                       * with any SIGCHLD management happening in the application. */
                      ctx, &pidfd);

    r = restore_thread_after_clone(ctx, errbuf, sizeof(errbuf));
    if (r == -1) {
        raising_error = true;
    }

    if (pid == -1) {
        snprintf(errbuf, sizeof(errbuf), "error calling clone(2): %s",
                 strerror_r(errno, strerror_buf, sizeof(strerror_buf)));
        raising_error = true;
    }
    if (pid > 0 && !raising_error) {
        /* Hooray, our clone worked! Did the child successfull exec? */
        if (ctx->have_child_error) {
            snprintf(errbuf, sizeof(errbuf), "%s", ctx->child_error);
            raising_error = true;

            /* this means the thing has exited, need to wait on it. */
            r = waitid(P_PIDFD, pidfd, NULL, WEXITED | __WCLONE | WNOHANG);
            if (r == 0) {
                snprintf(errbuf, sizeof(errbuf), "waitid(2) found no children on error");
                raising_error = true;
            }
            if (r == -1) {
                snprintf(errbuf, sizeof(errbuf), "error calling waitid(2) after failure: %s",
                         strerror_r(errno, strerror_buf, sizeof(strerror_buf)));
                raising_error = true;
            }
            close(pidfd);
        }
    }

    if (raising_error) {
        rb_raise(rb_eRuntimeError, "%s", errbuf);
    }

    /* all is well, return. */
    VALUE ret_array = rb_ary_resize(rb_ary_new(), 2);
    RARRAY_ASET(ret_array, 0, RB_INT2NUM(pid));
    RARRAY_ASET(ret_array, 1, profile_wrap_fd_in_io(pidfd));    

    RB_GC_GUARD(spawn_context_wrapper);

    return ret_array;
}

static VALUE
profile_linux_s_pidfd_wait(VALUE klass, VALUE pidfd_io)
{
    rb_io_wait(pidfd_io, RB_INT2NUM(RUBY_IO_READABLE), Qfalse);
    int pidfd = RB_NUM2INT(rb_funcall(pidfd_io, rb_intern("fileno"), 0));
    siginfo_t info;
    int r = waitid(P_PIDFD, pidfd, &info, WEXITED | __WCLONE | WNOHANG);
    if (r == 0) {
        rb_raise(rb_eRuntimeError, "no child exited after pidfd was readable");
    }
    if (r == -1) {
        rb_sys_fail("waitid(2) failed after pidfd was readable");
    }
    /* Would be cool to return a Process::Status, but it has no public constructor. */
    return RB_INT2NUM(info.si_status);
}

static VALUE
profile_linux_s_pidfd_wait_nonblock(VALUE klass, VALUE pidfd_io)
{
    int pidfd = RB_NUM2INT(rb_funcall(pidfd_io, rb_intern("fileno"), 0));
    siginfo_t info;
    int r = waitid(P_PIDFD, pidfd, &info, WEXITED | __WCLONE | WNOHANG);
    if (r == 0) {
        return Qnil;
    }
    if (r == -1) {
        rb_sys_fail("waitid(2) failed after pidfd was readable");
    }
    return RB_INT2NUM(info.si_status);
}

void
init_profile_linux(void)
{
    mProfileLinux = rb_define_module_under(mProfile, "Linux");
    rb_define_singleton_method(mProfileLinux, "spawn_private",
                               profile_linux_s_spawn_private, 2);
    rb_define_singleton_method(mProfileLinux, "pidfd_wait",
                               profile_linux_s_pidfd_wait, 1);
    rb_define_singleton_method(mProfileLinux, "pidfd_wait_nonblock",
                               profile_linux_s_pidfd_wait_nonblock, 1);
}
