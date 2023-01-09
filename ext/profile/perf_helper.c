#include <bpf/libbpf.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/limits.h>
#include <linux/perf_event.h>
#include <linux/hw_breakpoint.h>
#include <search.h>
#include <signal.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/un.h>
#include <unistd.h>

#include "stack_sample.bpf.h"
#include "stack_sample.skel.h"
#include "perf_helper_message.h"

#define SOCKET_FD 3

/* A normal xmalloc wrapper */
static void *
xmalloc(size_t n)
{
    void *r = malloc(n);
    if (!r) {
        abort();
    }
    return r;
}

/*
 * =============================================================================
 * numtable hash table impl
 * =============================================================================
 */

/* The numtable struct is a simple hashtable mapping int -> void *. It uses open
 * addressing with linear probing, and implements deletes with tombstones.
 * This is only nescessary because st.c can't really be used outside of the Ruby
 * interpreter - it _appears_ to have some pre-processor support for doing this,
 * but it no longer works it seems. */
struct numtable {
    struct numtable_impl {
        struct numtable_entry {
            bool occupied : 1;
            bool tombstone : 1;
            int key;
            uintptr_t value;
        } *entries;
        size_t capa;
        size_t len;
        size_t tombstone_count;
    } impl;
};

#define NUMTABLE_SLOT_NEW 0
#define NUMTABLE_SLOT_EXISTING 1
#define NUMTABLE_ITER_STOP 0
#define NUMTABLE_ITER_CONTINUE 1
#define NUMTABLE_NOT_FOUND 0
#define NUMTABLE_FOUND 1

static void
numtable_init(struct numtable *tab, size_t initial_capa)
{
    tab->impl.capa = initial_capa;
    tab->impl.len = 0;
    tab->impl.tombstone_count = 0;
    tab->impl.entries = xmalloc(sizeof(struct numtable_entry) * tab->impl.capa);
    memset(tab->impl.entries, 0, sizeof(struct numtable_entry) * tab->impl.capa);
}

/* I copied this hash algorithm from st.c */
static unsigned long
numtable_hash(int key)
{
    enum {s1 = 11, s2 = 3};
    unsigned long h = (unsigned long)((key>>s1|(key<<s2)) ^ (key>>s2));
    return h;
}

static int
numtable_find_slot(struct numtable_impl *tab, int key, struct numtable_entry **entry_out)
{
    unsigned long hash = numtable_hash(key);
    size_t i = hash % tab->capa;
    struct numtable_entry *slot;
    /* Termination guaranteed because we ensure the load factor is < 25% at all times; so,
     * there _MUST_ be !occupied && !tombstone slots somewhere */
    while (true) {
        slot = &tab->entries[i];
        if (slot->occupied && slot->key == key) {
            *entry_out = slot;
            return NUMTABLE_SLOT_EXISTING;
        }
        if (!slot->occupied && !slot->tombstone) {
            *entry_out = slot;
            return NUMTABLE_SLOT_NEW;
        }
        i++;
        if (i >= tab->capa) {
            i = 0;
        }
    }
}

static void
numtable_grow_if_required(struct numtable *tab)
{
    if ((tab->impl.len + tab->impl.tombstone_count) * 4 <= tab->impl.capa) {
        return;
    }

    struct numtable_impl new_impl = { 0 };
    struct numtable_impl *old_impl = &tab->impl;
    new_impl.capa = old_impl->capa * 2;
    new_impl.len = old_impl->len;
    new_impl.tombstone_count = 0;
    new_impl.entries = xmalloc(sizeof(struct numtable_entry) * new_impl.capa);
    memset(new_impl.entries, 0, sizeof(struct numtable_entry) * new_impl.capa);

    for (size_t i = 0; i < old_impl->capa; i++) {
        if (!old_impl->entries[i].occupied) {
            continue;
        }
        struct numtable_entry *new_slot;
        numtable_find_slot(&new_impl, old_impl->entries[i].key, &new_slot);
        new_slot->occupied = true;
        new_slot->tombstone = false;
        new_slot->key = old_impl->entries[i].key;
        new_slot->value = old_impl->entries[i].value;
    }

    free(old_impl->entries);
    tab->impl = new_impl;
}

static int
numtable_get(struct numtable *tab, int key, uintptr_t *val_out)
{
    struct numtable_entry *slot;
    int r = numtable_find_slot(&tab->impl, key, &slot);
    if (r == NUMTABLE_SLOT_EXISTING) {
        *val_out = slot->value;
        return NUMTABLE_FOUND;
    }
    return NUMTABLE_NOT_FOUND;
}

static int
numtable_set(struct numtable *tab, int key, uintptr_t new_val, uintptr_t *old_val)
{
    numtable_grow_if_required(tab);

    struct numtable_entry *slot;
    int r = numtable_find_slot(&tab->impl, key, &slot);
    if (r == NUMTABLE_SLOT_EXISTING) {
        if (old_val) {
            *old_val = slot->value;
        }
    }
    slot->occupied = true;
    slot->tombstone = false;
    slot->key = key;
    slot->value = new_val;
    return r;
}

static int
numtable_delete(struct numtable *tab, int key, uintptr_t *old_val)
{
    numtable_grow_if_required(tab);

    struct numtable_entry *slot;
    int r = numtable_find_slot(&tab->impl, key, &slot);
    if (r == NUMTABLE_SLOT_EXISTING) {
        *old_val = slot->value;
    }
    slot->occupied = false;
    slot->tombstone = true;
    return r;
    
}

typedef int (*numtable_iter_func)(int key, uintptr_t val, void *ctx);

static void
numtable_each(struct numtable *tab, numtable_iter_func iter_func, void *ctx)
{
    for (size_t i = 0; i < tab->impl.capa; i++) {
        struct numtable_entry *ent = &tab->impl.entries[i];
        if (ent->occupied && !ent->tombstone) {
            int r = iter_func(ent->key, ent->value, ctx);
            if (r == NUMTABLE_ITER_STOP) {
                break;
            }
        }
    }
}

/*
 * =============================================================================
 * Helper main data structures
 * =============================================================================
 */

#define EPOLL_FD_TYPE_SOCKET 1
#define EPOLL_FD_TYPE_THREAD 2

/* Type of data we stash in epoll */
struct event_loop_epoll_data {
    int fd;
    int fd_type;
    pid_t tid;
};

struct thread_data {
    /* the thread being profiled */
    pid_t tid;
    int tid_fd;

    /* perf_event_open handle for this thread */
    int perf_fd;

    /* libbpf link (attachment to perf_fd) */
    struct bpf_link *stack_sample_attachment;

    struct event_loop_epoll_data epoll_data;
};

struct prof_data {
    int epoll_fd;       /* main run-loop epoll descriptor */
    int socket_fd;      /* socket we communicate with the profiled process on */
    struct event_loop_epoll_data socket_fd_epoll_data;
    

    /* Information about the process on the other side of the socket */
    struct ucred caller_creds;  /* original creds from the socket */
    pid_t caller_pid;           /* remote pid (actually a thread-group-id) */
    int caller_pid_fd;          /* pidfd for pid */

    /* Configuration values sent to us by the peer in the setup
     * message */
    uint32_t max_threads;

    /* Profiling resources */
    int perf_group_fd;  /* main perf FD that all other perf FDs are a child of */
    struct stack_sample_bpf *stack_sample_skel; /* libbpf program handle */

    /* map of per-thread struct thread_data's */
    struct numtable thread_table;
};

struct strbuf {
    size_t len;
    char str[];
};

/*
 * =============================================================================
 * Syscall wrappers not provided by glibc
 * =============================================================================
 */

static int
perf_event_open(struct perf_event_attr *hw_event, pid_t pid, int cpu,
                int group_fd, unsigned long flags)
{
    return syscall(__NR_perf_event_open, hw_event, pid, cpu, group_fd, flags);
}

static int
pidfd_open(pid_t pid, unsigned int flags)
{
    return syscall(SYS_pidfd_open, pid, flags);
}

static int
pidfd_send_signal(int pidfd, int sig, siginfo_t *info, unsigned int flags)
{
    return syscall(SYS_pidfd_send_signal, pidfd, sig, info, flags);
}

/*
 * =============================================================================
 * Message i/o routines
 * =============================================================================
 */

static int
read_socket_message(int socket_fd, struct perf_helper_msg *msg_out, struct strbuf *errbuf)
{
    return read_perf_helper_message(socket_fd, msg_out, errbuf->str, errbuf->len);
}

static int
write_socket_message(int socket_fd, struct perf_helper_msg *msg, struct strbuf *errbuf)
{
    return write_perf_helper_message(socket_fd, msg, errbuf->str, errbuf->len);
}

/*
 * =============================================================================
 * PID and credential validation routines
 * =============================================================================
 */

static int
validate_socket_peercred_matches_parent(int socket_fd, struct strbuf *errbuf)
{
    struct ucred creds;
    socklen_t sizeof_ucred = sizeof(struct ucred);
    int r = getsockopt(socket_fd, SOL_SOCKET, SO_PEERCRED, &creds, &sizeof_ucred);
    if (r == -1) {
        snprintf(errbuf->str, errbuf->len,
                 "could not get percred from socket: %s", strerror(errno));
        return -1;
    }
    pid_t parent_pid = getppid();
    if (creds.pid != parent_pid) {
        snprintf(errbuf->str, errbuf->len,
                 "socket credentials pid %d did not match parent pid %d", creds.pid, parent_pid);
        return -1;
    }
    return 0;
}

__attribute__(( format(scanf, 2, 4) ))
static int
read_pattern_from_procfile(char *fname, const char *pattern, struct strbuf *errbuf, ...)
{
    va_list args;
    va_start(args, errbuf);
    int ret = 0;
    FILE *f = fopen(fname, "r");
    if (f == NULL) {
        snprintf(errbuf->str, errbuf->len,
                 "error opening %s: %s", fname, strerror(errno));
        ret = -1;
        goto out;
    }
    bool partline = false;
    char linebuf[256];
    while (!feof(f)) {
        if (fgets(linebuf, sizeof(linebuf), f) == NULL) {
          snprintf(errbuf->str, errbuf->len,
                   "error reading file %s: %s", fname, strerror(ferror(f)));
          ret = -1;
          goto out;
        }
        if (!partline) {
            if (vsscanf(linebuf, pattern, args) > 0) {
                ret = 1;
                goto out;
            }
        }
        partline = !strchr(linebuf, '\n');
    }
out:
    va_end(args);
    if (f) {
        fclose(f);
    }
    return ret; 
}

static int
pidfd_alive(int pidfd, pid_t pidfd_pid, struct strbuf *errbuf)
{
    if (pidfd_send_signal(pidfd, 0, NULL, 0) < 0) {
        /* means there could be pid re-use */
        snprintf(errbuf->str, errbuf->len,
                 "pidfd_send_signal(2) failed (pid %d exited?): %s", pidfd_pid, strerror(errno));
        return -1;
    }

    return 0;
}

static int
validate_pidfd_pid_matches(pid_t pid, int pidfd, struct strbuf *errbuf)
{
    /* First, need to find what pid this pidfd is for */
    char fname[PATH_MAX];
    snprintf(fname, sizeof(fname), "/proc/self/fdinfo/%d", pidfd);
    pid_t pidfd_pid;
    int r = read_pattern_from_procfile(fname, "Pid: %d", errbuf, &pidfd_pid);
    if (r == -1) {
        return r;
    } else if (r == 0) {
        snprintf(errbuf->str, errbuf->len,
                 "Pid: line not in %s (not a pidfd?)", fname);
        return -1;
    }

    if (pidfd_pid != pid) {
        snprintf(errbuf->str, errbuf->len,
                 "ucreds pid (%d) did not match pidfd pid (%d)", pid, pidfd_pid);
        return -1;
    }

    if (pidfd_alive(pidfd, pidfd_pid, errbuf) == -1) {
        return -1;
    }
    return 0;
}

static int
validate_creds_match_self(struct ucred creds, struct strbuf *errbuf)
{
    uid_t uid = getuid();
    if (creds.uid != uid) {
        snprintf(errbuf->str, errbuf->len,
                 "uid does not match requester (%u vs %u)", creds.uid, uid);
        return -1;
    }
    uid_t gid = getuid();
    if (creds.gid != gid) {
        snprintf(errbuf->str, errbuf->len,
                 "gid does not match requester (%u vs %u)", creds.gid, gid);
        return -1;
    }
    return 0; 
}

static int
get_thread_tgid(pid_t pid, pid_t *tgid_out, struct strbuf *errbuf)
{
    char status_fname[PATH_MAX];
    snprintf(status_fname, sizeof(status_fname), "/proc/%d/status", pid);
    int r = read_pattern_from_procfile(status_fname, "Tgid: %d", errbuf, tgid_out);
    if (r == -1) {
        return -1;
    } else if (r == 0) {
        snprintf(errbuf->str, errbuf->len,
                 "no Tgid line in %s", status_fname);
        return -1;
    }
    return 0;
}

/*
 * =============================================================================
 * Main message handling functions
 * =============================================================================
 */

static int
handle_thread_exit(struct prof_data *state, pid_t tid, struct strbuf *errbuf)
{
    uintptr_t th_data_entry;
    int r = numtable_delete(&state->thread_table, tid, &th_data_entry);
    if (r == NUMTABLE_SLOT_NEW) {
        /* it wasn't in here?? */
        return 0;
    }
    struct thread_data *thdata = (struct thread_data *)th_data_entry;
    if (thdata->stack_sample_attachment) {
        bpf_link__detach(thdata->stack_sample_attachment);
    }
    if (thdata->perf_fd != -1) {
        close(thdata->perf_fd);
    }
    if (thdata->tid_fd != -1) {
        epoll_ctl(state->epoll_fd, EPOLL_CTL_DEL, thdata->tid_fd, NULL);
        close(thdata->tid_fd);
    }
    bpf_map__delete_elem(state->stack_sample_skel->maps.thread_data, &tid, sizeof(pid_t), 0);
    free(thdata);
    return 0;
}

static int
handle_message_setup(struct prof_data *state, struct perf_helper_msg msg, struct strbuf *errbuf)
{
    int ret;
    int dummy_fd = -1;
    int caller_pid_fd = -1;
    struct stack_sample_bpf *stack_sample_skel = NULL;

    /* Validate the credentials present in the message */
    if (!msg.ancdata.have_creds) {
        snprintf(errbuf->str, errbuf->len,
                 "did not receive SCM_CREDENTIALS message");
        ret = -1;
        goto out;
    }
    if (msg.ancdata.fd_count != 1) {
        snprintf(errbuf->str, errbuf->len,
                 "received wrong number of FDs (got %zu)", msg.ancdata.fd_count);
        ret = -1;
        goto out;
    }
    caller_pid_fd = msg.ancdata.fds[0];
    /* validate that the pidfd we got really is for the caller's pid, and that it's still live
     * and thus that there has been no pid reuse */
    if (validate_pidfd_pid_matches(msg.ancdata.creds.pid, caller_pid_fd, errbuf) == -1) {
        ret = -1;
        goto out;
    }
    /* also validate uid/gid are the same - this _should_ be a no-op */
    if (validate_creds_match_self(msg.ancdata.creds, errbuf) == -1) {
        ret = -1;
        goto out;
    }
    

    /* To handle the setup req, we need to set up the eBPF machinery, and a dummy
     * perf handle we can use as a group leader */
    struct perf_event_attr dummy_attr = { 0 };
    dummy_attr.size = sizeof(struct perf_event_attr);
    dummy_attr.type = PERF_TYPE_SOFTWARE;
    dummy_attr.config = PERF_COUNT_SW_DUMMY;
    dummy_attr.sample_freq = 1;
    dummy_attr.freq = 1;
    dummy_fd = perf_event_open(&dummy_attr, msg.ancdata.creds.pid, -1, -1, PERF_FLAG_FD_CLOEXEC);
    if (dummy_fd == -1) {
        snprintf(errbuf->str, errbuf->len,
                 "perf_event_open(2) for dummy event failed: %s", strerror(errno));
        ret = -1;
        goto out;
    }

    /* need to re-validate that the pid we just bound dummy_fd to is the same one we had
     * the pidfd for, and not re-used, by checking the pidfd is still alive */
    if (pidfd_send_signal(caller_pid_fd, 0, NULL, 0) < 0) {
        snprintf(errbuf->str, errbuf->len,
                 "pidfd_send_signal(2) failed (pid %d exited?): %s", msg.ancdata.creds.pid, strerror(errno));
        ret = -1;
        goto out;
    }

    stack_sample_skel = stack_sample_bpf__open_and_load();
    if (stack_sample_skel == NULL) {
        snprintf(errbuf->str, errbuf->len,
                 "failed to open stack sample bpf program: %s", strerror(errno));
        ret = -1;
        goto out;
    }

    int r = bpf_map__set_max_entries(stack_sample_skel->maps.thread_data, msg.body.req_setup.max_threads);
    if (r < 0) {
        snprintf(errbuf->str, errbuf->len,
                 "failed to resize thread_pids bpf map: %s", strerror(-r));
        ret = -1;
        goto out;
    }

    /* move all resources over to state so they don't get freed by
     * the out: block below. */
    state->perf_group_fd = dummy_fd;
    dummy_fd = -1;
    state->caller_pid_fd = caller_pid_fd;
    caller_pid_fd = -1;
    state->stack_sample_skel = stack_sample_skel;
    stack_sample_skel = NULL;
    state->max_threads = msg.body.req_setup.max_threads;
    state->caller_creds = msg.ancdata.creds;
    state->caller_pid = msg.ancdata.creds.pid;

    struct perf_helper_msg res = { 0 };
    res.body.type = PERF_HELPER_MSG_RES_SETUP;
    res.ancdata.fd_count = 2;
    res.ancdata.fds[0] = state->perf_group_fd;
    res.ancdata.fds[1] = bpf_map__fd(state->stack_sample_skel->maps.events);
    r = write_socket_message(state->socket_fd, &res, errbuf);
    if (r == -1) {
        ret = -1;
        goto out;
    }
    ret = 0;

out:
    if (stack_sample_skel) {
        stack_sample_bpf__destroy(stack_sample_skel);
    }
    if (dummy_fd != -1) {
        close(dummy_fd);
    }
    if (caller_pid_fd != -1) {
        close(caller_pid_fd);
    }
    return ret;
}

static int
handle_message_newthread(struct prof_data *state, struct perf_helper_msg msg, struct strbuf *errbuf)
{
    int ret;
    int thread_pidfd = -1;
    int perf_fd = -1;
    pid_t thread_tid = 0;
    struct bpf_link *stack_sample_link = NULL;

    if (msg.ancdata.fd_count != 1) {
        snprintf(errbuf->str, errbuf->len,
                 "received wrong number of FDs (got %zu)", msg.ancdata.fd_count);
        ret = -1;
        goto out;
    }
    thread_pidfd = msg.ancdata.fds[0];

    /* validate that the pidfd == the pid we were given */
    thread_tid = msg.body.req_newthread.thread_tid;
    if (validate_pidfd_pid_matches(thread_pidfd, thread_tid, errbuf) == -1) {
        ret = -1;
        goto out;
    }

    /* verify that this thread belongs to the same process as we're connected to */
    pid_t thread_tgid;
    if (get_thread_tgid(thread_tid, &thread_tgid, errbuf) == -1) {
        ret = -1;
        goto out;
    }

    if (thread_tgid != state->caller_pid) {
        snprintf(errbuf->str, errbuf->len,
                 "thread belongs to a different process (%d, expected %d)",
                 thread_tgid, state->caller_pid);
        ret = -1;
        goto out;
    }

    /* Check if we already have an entry in progress for this pid; if so, close
     * it off. handle_thread_exit will successfully do nothing if we didn't already
     * know about thread_pid. */
    int r = handle_thread_exit(state, thread_tid, errbuf);
    if (r == -1) {
        ret = -1;
        goto out;
    } 

    struct perf_event_attr perf_attr = { 0 };
    perf_attr.size = sizeof(struct perf_event_attr);
    perf_attr.type = PERF_TYPE_SOFTWARE;
    perf_attr.config = PERF_COUNT_SW_TASK_CLOCK;
    perf_attr.sample_freq = msg.body.req_newthread.interval_hz;
    perf_attr.freq = 1;
    perf_fd = perf_event_open(&perf_attr, thread_tid, -1, state->perf_group_fd, PERF_FLAG_FD_CLOEXEC);
    if (perf_fd == -1) {
        snprintf(errbuf->str, errbuf->len,
                 "perf_event_open(2) for dummy event failed: %s", strerror(errno));
        ret = -1;
        goto out;
    }

    /* check for pid re-use */
    if (pidfd_alive(thread_pidfd, thread_tid, errbuf) == -1) {
        ret = -1;
        goto out;
    }
    
    stack_sample_link = bpf_program__attach_perf_event(state->stack_sample_skel->progs.stack_sample, perf_fd);
    if (!stack_sample_link) {
        snprintf(errbuf->str, errbuf->len,
                 "bpf attach failed: %s", strerror(errno));
        ret = -1;
        goto out;
    }


    struct stack_sample_thread_data map_data;
    map_data.pid = thread_tid;
    map_data.ruby_stack_ptr = msg.body.req_newthread.ruby_stack_ptr;
    r = bpf_map__update_elem(state->stack_sample_skel->maps.thread_data, &thread_tid, sizeof(pid_t),
                             &map_data, sizeof(struct stack_sample_thread_data),
                             0);
    if (r < 0) {
        snprintf(errbuf->str, errbuf->len,
                 "failed to update ebpf map: %s", strerror(-r));
        ret = -1;
        goto out;
      }


    struct thread_data *thdata = xmalloc(sizeof(struct thread_data));
    struct epoll_event ev;
    thdata->epoll_data.fd = thread_pidfd;
    thdata->epoll_data.tid = thread_tid;
    thdata->epoll_data.fd_type = EPOLL_FD_TYPE_THREAD;
    ev.events = EPOLLIN | EPOLLERR | EPOLLHUP;
    ev.data.ptr = &thdata->epoll_data;
    r = epoll_ctl(state->epoll_fd, EPOLL_CTL_ADD, thdata->tid_fd, &ev);
    if (r == -1) {
        snprintf(errbuf->str, errbuf->len,
                 "failed to epoll_ctl add pidfd: %s", strerror(errno));
        ret = -1;
        free(thdata);
        goto out;
    }

    /* If we got here, save the FDs and null them out so they don't get closed
     * by the out: block */
    thdata->tid = thread_tid;
    thdata->tid_fd = thread_pidfd;
    thread_pidfd = -1;
    thdata->perf_fd = perf_fd;
    perf_fd = -1;
    thdata->stack_sample_attachment = stack_sample_link;
    stack_sample_link = NULL;
    numtable_set(&state->thread_table, thread_tid, (uintptr_t)thdata, NULL);

    /* Send the response message */
    struct perf_helper_msg res = { 0 };
    res.body.type = PERF_HELPER_MSG_RES_NEWTHREAD;
    r = write_socket_message(state->socket_fd, &res, errbuf);
    if (r == -1) {
        ret = -1;
        goto out;
    }
    ret = 0;
out:
    if (ret == -1 && thread_tid != 0) {
        /* on error, ensure we removed any pid we added to the bpf map */
        bpf_map__delete_elem(state->stack_sample_skel->maps.thread_data, &thread_tid, sizeof(pid_t), 0);
    }
    if (stack_sample_link) {
        bpf_link__detach(stack_sample_link);
    }
    if (thread_pidfd != -1) {
        close(thread_pidfd);
    }
    if (perf_fd != -1) {
        close(perf_fd);
    }
    return ret;
}

static int
handle_message_endthread(struct prof_data *state, struct perf_helper_msg msg, struct strbuf *errbuf)
{
    if (msg.ancdata.fd_count != 0) {
        snprintf(errbuf->str, errbuf->len,
                 "received wrong number of FDs (got %zu)", msg.ancdata.fd_count);
        return -1;
    }

    int r = handle_thread_exit(state, msg.body.req_endthread.thread_tid, errbuf);
    if (r == -1) {
        return -1;
    }

    struct perf_helper_msg res = { 0 };
    res.body.type = PERF_HELPER_MSG_RES_ENDTHREAD;
    r = write_socket_message(state->socket_fd, &res, errbuf);
    if (r == -1) {
        return -1;
    }
    return 0;
}

static int
handle_message(struct prof_data *state, struct perf_helper_msg msg, struct strbuf *errbuf)
{
    switch (msg.body.type) {
      case PERF_HELPER_MSG_REQ_SETUP:
        return handle_message_setup(state, msg, errbuf);
      case PERF_HELPER_MSG_REQ_NEWTHREAD:
        return handle_message_newthread(state, msg, errbuf);
      case PERF_HELPER_MSG_REQ_ENDTHREAD:
        return handle_message_endthread(state, msg, errbuf);
      default:
        snprintf(errbuf->str, errbuf->len,
                 "unknown received message type %d", msg.body.type);
        return -1;
    }
}

/*
 * =============================================================================
 * Event loop handling
 * =============================================================================
 */

static int
setup_event_loop(struct prof_data *state, struct strbuf *errbuf)
{
    /* event loop fd */
    state->epoll_fd = epoll_create1(EPOLL_CLOEXEC);
    if (state->epoll_fd == -1) {
        snprintf(errbuf->str, errbuf->len,
                 "failed to call epoll_create1(2): %s", strerror(errno));
        return -1;
    }
    /* The unix socketpair we listen on needs to be passed in as FD 3 */
    state->socket_fd = SOCKET_FD;
    state->socket_fd_epoll_data.fd = state->socket_fd;
    state->socket_fd_epoll_data.fd_type = EPOLL_FD_TYPE_SOCKET;
    struct epoll_event ev;
    ev.events = EPOLLIN | EPOLLERR | EPOLLHUP;
    ev.data.ptr = &state->socket_fd_epoll_data;
    int r = epoll_ctl(state->epoll_fd, EPOLL_CTL_ADD, state->socket_fd, &ev);
    if (r == -1) {
        snprintf(errbuf->str, errbuf->len,
                 "failed to arm socket_fd with epoll_ctl(2): %s", strerror(errno));
        return -1;
    }
    return 0;
}

static int
run_event_loop(struct prof_data *state, struct strbuf *errbuf)
{
    while (true) {
        struct epoll_event event;
        int r = epoll_wait(state->epoll_fd, &event, 1, -1);
        if (r == -1) {
            snprintf(errbuf->str, errbuf->len,
                     "failed to poll epoll_wait(2): %s", strerror(errno));
            return -1;
        }

        /* What fd fired? */
        struct event_loop_epoll_data *evdata = event.data.ptr;
        struct perf_helper_msg msg;
        switch (evdata->fd_type) {
          case EPOLL_FD_TYPE_SOCKET:
            /* handle message on main socket */
            r = read_socket_message(evdata->fd, &msg, errbuf);
            if (r == -1) {
                return -1;
            } else if (r == 0) {
                /* ?? no message was available in the end ?? */
                break;
            }
            r = handle_message(state, msg, errbuf);
            if (r == -1) {
                return -1;
            }
            break;
          case EPOLL_FD_TYPE_THREAD:
            /* a thread we were following exited */
            r = handle_thread_exit(state, evdata->tid, errbuf);
            if (r == -1) {
                return -1;
            }
            break;
        }
    }
    return 0;
}

/*
 * =============================================================================
 * Main function & friends
 * =============================================================================
 */

static void
init_state(struct prof_data *state)
{
    memset(state, 0, sizeof(struct prof_data));
    state->epoll_fd = -1;
    state->socket_fd = -1;
    state->caller_pid_fd = -1;
    state->perf_group_fd = -1;
    numtable_init(&state->thread_table, 16);
}

static int 
cleanup_thread_state_iter(int key, uintptr_t val, void *ctx)
{
    struct thread_data *data = (struct thread_data *)val;
    if (data->stack_sample_attachment) {
        bpf_link__detach(data->stack_sample_attachment);
    }
    if (data->perf_fd != -1) {
        close(data->perf_fd);
    }
    if (data->tid_fd != -1) {
        close(data->tid_fd);
    }
    free(data);
    return NUMTABLE_ITER_CONTINUE;
}

static void
cleanup_state(struct prof_data *state)
{
    numtable_each(&state->thread_table, cleanup_thread_state_iter, NULL);
    if (state->stack_sample_skel) {
        stack_sample_bpf__destroy(state->stack_sample_skel);
    }
    if (state->perf_group_fd != -1) {
        close(state->perf_group_fd);
    }
    if (state->caller_pid_fd != -1) {
        close(state->caller_pid_fd);
    }
    if (state->epoll_fd != -1) {
        close(state->epoll_fd);
    }
}


int
main(int argc, char **argv)
{
    /* See the comment in perf_helper.h for a description of the security checks taken
     * by this program to ensure that a calling program can't ask to profile a thread in a
     * different program */

    /* Start with some normal defence-in-depth stuff which is good practice for suid programs */
    /* We have no need for a process environment at all */
    clearenv();
    /* We don't use stdin/stdout at all */
    close(STDIN_FILENO);
    close(STDOUT_FILENO);
    /* Don't need SIGPIPE, we'll find out that the socket is closed by error handling */
    signal(SIGPIPE, SIG_IGN);

    /* Our stderr & socket fds come through as O_NONBLOCK, but we actually expect
     * blocking behaviour in this program */
    int fds[2] = { STDERR_FILENO, SOCKET_FD };
    for (int i = 0; i < 2; i++) {
        int fl_flags = fcntl(fds[i], F_GETFL);
        if (fl_flags == -1) {
            fprintf(stderr, "error calling fcntl(2) F_GETFL: %s", strerror(errno));
            exit(1);
        }
        fl_flags &= ~O_NONBLOCK;
        if (fcntl(fds[i], F_SETFL, fl_flags) == -1) {
            fprintf(stderr, "error calling fcntl(2) F_GETFL: %s", strerror(errno));
            exit(1);
        }
    }

    /* Zero out our state structure */
    struct prof_data state;
    init_state(&state);
    struct strbuf *errbuf = alloca(sizeof(struct strbuf) + 512);
    errbuf->len = 512;
    errbuf->str[0] = '\0';

    /* Sets up our event loop infrastructure */
    if (setup_event_loop(&state, errbuf) == -1) {
        fprintf(stderr, "%s\n", errbuf->str);
        exit(1);
    }

    /* This check is not strictly speaking needed, but included in the interests of defence
     * in depth. Ensure that the socket we received was actually bound by our parent process.
     * Note that this is not at all a sufficient check on its own because if our parent process
     * had a socket pair that came e.g. from init (pid1), and promptly exited after forking us,
     * we might conclude that our parent (init) owns the socket and all is OK */
    if (validate_socket_peercred_matches_parent(state.socket_fd, errbuf) == -1) {
        fprintf(stderr, "%s\n", errbuf->str);
        exit(1);
    }

    /* Loop waiting for messages or closed processes */
    int ret;
    if (run_event_loop(&state, errbuf) == -1) {
        fprintf(stderr, "%s\n", errbuf->str);
        ret = 1;
    } else {
        ret = 0;
    }

    cleanup_state(&state);
    exit(ret);
    return 0;
}
