#include <bpf/libbpf.h>
#include <errno.h>
#include <linux/limits.h>
#include <linux/perf_event.h>
#include <linux/hw_breakpoint.h>
#include <search.h>
#include <signal.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/un.h>
#include <unistd.h>

#include "perf_helper.h"
#include "stack_sample.bpf.h"
#include "stack_sample.skel.h"

#define SOCKET_FD 3
#define PARENT_PID_FD 4
#define PERF_GROUP_LEADER_FD 5
#define NUM_RESPONSE_FDS 4

/* A big buffer makes a bunch of truncation errors go away, and I don't really
 * care about how much memory this uses or whether or not error messages
 * get truncated */
char error_message[512 + PATH_MAX];

struct per_proc_struct {
    bool present : 1;
    bool tombstone : 1;
    unsigned long hash;

    pid_t pid;
    int pidfd;
    uintptr_t thread_stack_ptr;
};

struct proc_table_impl {
  struct per_proc_struct *entries;
  size_t size;
  size_t capa;
  size_t tombstone_count;
};

static struct state_struct {
    int socket_fd;
    struct ucred caller_creds;
    uint32_t max_threads;
    int caller_pid_fd;
    pid_t caller_pid;
    int perf_group_fd;
    bool run_setup;
    struct stack_sample_bpf *stack_sample_skel;
    /* table of per_proc_struct, open addressing, linear probing */
    struct proc_table_impl proc_table;
} state;

static void *
xmalloc(size_t n)
{
    void *r = malloc(n);
    if (!r) {
        abort();
    }
    return r;
}

static unsigned long
hash_pid(pid_t pid)
{
    enum {s1 = 11, s2 = 3};
    unsigned long h = (unsigned long)((pid>>s1|(pid<<s2)) ^ (pid>>s2));
    return h;
}

static int
find_proc_table_slot(struct proc_table_impl *tab, pid_t pid, struct per_proc_struct **slot_out)
{
    unsigned long hash = hash_pid(pid);
    size_t i = hash % tab->capa;
    struct per_proc_struct *slot;
    while (true) {
        slot = &tab->entries[i];
        if (slot->present && slot->pid == pid) {
            *slot_out = slot;
            return 1;
        }
        if (!slot->present && !slot->tombstone) {
            *slot_out = slot;
            return 0;
        }
        i++;
        if (i >= tab->capa) {
            i = 0;
        }
    }
}

static void
init_proc_table(void)
{
    state.proc_table.size = 0;
    state.proc_table.capa = 16;
    state.proc_table.tombstone_count = 0;
    state.proc_table.entries = xmalloc(state.proc_table.capa * sizeof(struct per_proc_struct));
}

void
grow_proc_table(void)
{
    struct proc_table_impl new_table;
    new_table.capa = state.proc_table.capa * 2;
    new_table.size = state.proc_table.size;
    new_table.tombstone_count = 0;
    new_table.entries = xmalloc(new_table.capa * sizeof(struct per_proc_struct));
    memset(new_table.entries, 0, new_table.capa);

    for (size_t i = 0; i < state.proc_table.capa; i++) {
        struct per_proc_struct *entry = &state.proc_table.entries[i];
        if (!entry->present) {
            continue;
        }
        struct per_proc_struct *new_slot;
        find_proc_table_slot(&new_table, entry->pid, &new_slot);
        memcpy(new_slot, entry, sizeof(struct per_proc_struct));
    }

    free(state.proc_table.entries);
    state.proc_table = new_table;
}

static int
proc_table_insert(pid_t pid, struct per_proc_struct ent)
{
    struct proc_table_impl *proc_table = &state.proc_table;
    if (proc_table->size + proc_table->tombstone_count >= proc_table->capa / 2) {
        grow_proc_table();
        proc_table = &state.proc_table;
    }
    struct per_proc_struct *new_slot;
    int r = find_proc_table_slot(proc_table, pid, &new_slot);
    if (r == 0) {
        /* not already existing! */
        proc_table->size++;
    }
    ent.pid = pid;
    ent.hash = hash_pid(pid);
    ent.present = true;
    ent.tombstone = false;
    memcpy(new_slot, &ent, sizeof(struct per_proc_struct));
    return r;
}

static int
proc_table_delete(pid_t pid, struct per_proc_struct *ret_ent)
{
    struct proc_table_impl *proc_table = &state.proc_table;
    struct per_proc_struct *found_slot;
    int r = find_proc_table_slot(proc_table, pid, &found_slot);
    if (r == 1) {
        /* it existed */
        memset(found_slot, 0, sizeof(struct per_proc_struct));
        found_slot->present = false;
        found_slot->tombstone = true;
        proc_table->size--;
        proc_table->tombstone_count++;
    }
    return r;
}

#define MAX_RECEIVED_FDS 16
struct received_message_with_ancdata {
    struct perf_helper_msg body;
    struct ucred creds;
    bool have_creds;
    int fds[MAX_RECEIVED_FDS];
    size_t fd_count;
};

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

static int
validate_socket_peercred_matches_parent(void)
{
    struct ucred creds;
    socklen_t sizeof_ucred = sizeof(struct ucred);
    int r = getsockopt(state.socket_fd, SOL_SOCKET, SO_PEERCRED, &creds, &sizeof_ucred);
    if (r == -1) {
        snprintf(error_message, sizeof(error_message),
                 "could not get percred from socket: %s", strerror(errno));
        return -1;
    }
    pid_t parent_pid = getppid();
    if (creds.pid != parent_pid) {
        snprintf(error_message, sizeof(error_message),
                 "socket credentials pid %d did not match parent pid %d", creds.pid, parent_pid);
        return -1;
    }
    return 0;
}


static int
read_socket_message(struct received_message_with_ancdata *msg_with_ancdata)
{
    union {
        struct cmsghdr align;
        char buf[
          /* space for a SCM_CREDENTIALS message */
          CMSG_SPACE(sizeof(struct ucred)) +
          /* space for SCM_RIGHTS */
          CMSG_SPACE(MAX_RECEIVED_FDS * sizeof(int))
        ];
    } cmsgbuf;
    memset(&cmsgbuf.buf, 0, sizeof(cmsgbuf.buf));

    struct iovec iov;
    iov.iov_base = &msg_with_ancdata->body;
    iov.iov_len = sizeof(struct perf_helper_msg);

    struct msghdr msg;
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;
    msg.msg_control = cmsgbuf.buf;
    msg.msg_controllen = sizeof(cmsgbuf.buf);
    msg.msg_flags = 0;

    int r = recvmsg(state.socket_fd, &msg, 0);
    if (r == -1) {
        snprintf(error_message, sizeof(error_message),
                 "error reading setup request message: %s", strerror(errno));
        return -1;
    }
    if (r == 0) {
        return 0;
    }

    if (r < (int)sizeof(struct perf_helper_msg)) {
        snprintf(error_message, sizeof(error_message),
                 "received message too small (%d bytes)", r);
        return -1;
    }

    msg_with_ancdata->have_creds = false;
    msg_with_ancdata->fd_count = 0;
    struct cmsghdr *cmsg = CMSG_FIRSTHDR(&msg);
    while (cmsg) {
        if (cmsg->cmsg_level == SOL_SOCKET && cmsg->cmsg_type == SCM_CREDENTIALS) {
            if (cmsg->cmsg_len != sizeof(struct ucred)) {
                snprintf(error_message, sizeof(error_message),
                         "size of SCM_CREDENTIALS message wrong (got %zu)", cmsg->cmsg_len);
                return -1;
            }
            memcpy(&msg_with_ancdata->creds, CMSG_DATA(cmsg), cmsg->cmsg_len);
            msg_with_ancdata->have_creds = true;
        } else if (cmsg->cmsg_level == SOL_SOCKET && cmsg->cmsg_type == SCM_RIGHTS) {
            if (cmsg->cmsg_len > MAX_RECEIVED_FDS * sizeof(int)) {
                snprintf(error_message, sizeof(error_message),
                         "size of SCM_RIGHTS message too high (got %zu)", cmsg->cmsg_len);
                return -1;
            }
            memcpy(msg_with_ancdata->fds, CMSG_DATA(cmsg), cmsg->cmsg_len);
            msg_with_ancdata->fd_count = cmsg->cmsg_len / sizeof(int);            
        }
        
        cmsg = CMSG_NXTHDR(&msg, cmsg);
    }
    return 0;
}

static int
write_socket_message(struct received_message_with_ancdata msg_with_ancdata)
{
    union {
        struct cmsghdr align;
        char buf[
          /* space for a SCM_CREDENTIALS message */
          CMSG_SPACE(sizeof(struct ucred)) +
          /* space for SCM_RIGHTS */
          CMSG_SPACE(MAX_RECEIVED_FDS * sizeof(int))
        ];
    } cmsgbuf;
    memset(&cmsgbuf.buf, 0, sizeof(cmsgbuf.buf));
    struct iovec iov;
    iov.iov_base = &msg_with_ancdata.body;
    iov.iov_len = sizeof(struct perf_helper_msg);

    struct msghdr msg;
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;
    msg.msg_control = cmsgbuf.buf;
    msg.msg_controllen = sizeof(cmsgbuf.buf);
    msg.msg_flags = 0;

    struct cmsghdr *cmsg = CMSG_FIRSTHDR(&msg);

    if (msg_with_ancdata.have_creds) {
        cmsg->cmsg_level = SOL_SOCKET;
        cmsg->cmsg_type = SCM_CREDENTIALS;
        cmsg->cmsg_len = CMSG_LEN(sizeof(struct ucred));
        memcpy(CMSG_DATA(cmsg), &msg_with_ancdata.creds, sizeof(struct ucred));
        cmsg = CMSG_NXTHDR(&msg, cmsg);
    }
    if (msg_with_ancdata.fd_count > 0 && msg_with_ancdata.fd_count < MAX_RECEIVED_FDS) {
        cmsg->cmsg_level = SOL_SOCKET;
        cmsg->cmsg_type = SCM_RIGHTS;
        cmsg->cmsg_len = CMSG_LEN(msg_with_ancdata.fd_count * sizeof(int));
        memcpy(CMSG_DATA(cmsg), msg_with_ancdata.fds, cmsg->cmsg_len);
        cmsg = CMSG_NXTHDR(&msg, cmsg);
    }

    int r = sendmsg(state.socket_fd, &msg, 0);
    if (r == -1) {
        snprintf(error_message, sizeof(error_message),
                 "sendmsg(2) failed: %s", strerror(errno));
        return -1;
    }

    return 0;
}

__attribute__(( format(scanf, 2, 3) ))
static int
read_pattern_from_procfile(char *fname, const char *pattern, ...)
{
    va_list args;
    va_start(args, pattern);
    int ret = 0;
    FILE *f = fopen(fname, "r");
    if (f == NULL) {
        snprintf(error_message, sizeof(error_message),
                 "error opening %s: %s", fname, strerror(errno));
        ret = -1;
        goto out;
    }
    bool partline = false;
    char linebuf[256];
    while (!feof(f)) {
        if (fgets(linebuf, sizeof(linebuf), f) == NULL) {
          snprintf(error_message, sizeof(error_message),
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
pidfd_alive(int pidfd, pid_t pidfd_pid)
{
    if (pidfd_send_signal(pidfd, 0, NULL, 0) < 0) {
        /* means there could be pid re-use */
        snprintf(error_message, sizeof(error_message),
                 "pidfd_send_signal(2) failed (pid %d exited?): %s", pidfd_pid, strerror(errno));
        return -1;
    }

    return 0;
}

static int
validate_pidfd_pid_matches(pid_t pid, int pidfd)
{
    /* First, need to find what pid this pidfd is for */
    char fname[PATH_MAX];
    snprintf(fname, sizeof(fname), "/proc/self/fdinfo/%d", pidfd);
    pid_t pidfd_pid;
    int r = read_pattern_from_procfile(fname, "Pid: %d", &pidfd_pid);
    if (r == -1) {
        return r;
    } else if (r == 0) {
        snprintf(error_message, sizeof(error_message),
                 "Pid: line not in %s (not a pidfd?)", fname);
        return -1;
    }

    if (pidfd_pid != pid) {
        snprintf(error_message, sizeof(error_message),
                 "ucreds pid (%d) did not match pidfd pid (%d)", pid, pidfd_pid);
        return -1;
    }

    if (pidfd_alive(pidfd, pidfd_pid) == -1) {
        return -1;
    }
    return 0;
}

static int
validate_creds_match(struct ucred creds)
{
    uid_t uid = getuid();
    if (creds.uid != uid) {
        snprintf(error_message, sizeof(error_message),
                 "uid does not match requester (%u vs %u)", creds.uid, uid);
        return -1;
    }
    uid_t gid = getuid();
    if (creds.gid != gid) {
        snprintf(error_message, sizeof(error_message),
                 "gid does not match requester (%u vs %u)", creds.gid, gid);
        return -1;
    }
    return 0; 
}

static int
get_thread_tgid(pid_t pid, pid_t *tgid_out)
{
    char status_fname[PATH_MAX];
    snprintf(status_fname, sizeof(status_fname), "/proc/%d/status", pid);
    int r = read_pattern_from_procfile(status_fname, "Tgid: %d", tgid_out);
    if (r == -1) {
        return -1;
    } else if (r == 0) {
        snprintf(error_message, sizeof(error_message),
                 "no Tgid line in %s", status_fname);
        return -1;
    }
    return 0;
}

static int
handle_message_setup(struct received_message_with_ancdata msg)
{
    int ret = -1;
    int dummy_fd = -1;
    struct stack_sample_bpf *stack_sample_skel = NULL;

    /* Validate the credentials present in the message */
    if (!msg.have_creds) {
        snprintf(error_message, sizeof(error_message),
                 "did not receive SCM_CREDENTIALS message");
        ret = -1;
        goto out;
    }
    if (msg.fd_count != 1) {
        snprintf(error_message, sizeof(error_message),
                 "received wrong number of FDs (got %zu)", msg.fd_count);
        ret = -1;
        goto out;
    }
    int caller_pid_fd = msg.fds[0];
    /* validate that the pidfd we got really is for the caller's pid, and that it's still live
     * and thus that there has been no pid reuse */
    if (validate_pidfd_pid_matches(msg.creds.pid, caller_pid_fd) == -1) {
        ret = -1;
        goto out;
    }
    /* also validate uid/gid are the same - this _should_ be a no-op */
    if (validate_creds_match(msg.creds) == -1) {
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
    dummy_fd = perf_event_open(&dummy_attr, msg.creds.pid, -1, -1, PERF_FLAG_FD_CLOEXEC);
    if (dummy_fd == -1) {
        snprintf(error_message, sizeof(error_message),
                 "perf_event_open(2) for dummy event failed: %s", strerror(errno));
        ret = -1;
        goto out;
    }

    /* need to re-validate that the pid we just bound dummy_fd to is the same one we had
     * the pidfd for, and not re-used, by checking the pidfd is still alive */
    if (pidfd_send_signal(caller_pid_fd, 0, NULL, 0) < 0) {
        snprintf(error_message, sizeof(error_message),
                 "pidfd_send_signal(2) failed (pid %d exited?): %s", msg.creds.pid, strerror(errno));
        ret = -1;
        goto out;
    }

    stack_sample_skel = stack_sample_bpf__open_and_load();
    if (stack_sample_skel == NULL) {
        snprintf(error_message, sizeof(error_message),
                 "failed to open stack sample bpf program: %s", strerror(errno));
        ret = -1;
        goto out;
    }

    int r = bpf_map__set_max_entries(stack_sample_skel->maps.thread_pids, msg.body.req_setup.max_threads);
    if (r < 0) {
        snprintf(error_message, sizeof(error_message),
                 "failed to resize thread_pids bpf map: %s", strerror(-r));
        ret = -1;
        goto out;
    }

    /* move all resources over to state so they don't get freed */
    state.perf_group_fd = dummy_fd;
    dummy_fd = -1;
    state.caller_pid_fd = caller_pid_fd;
    caller_pid_fd = -1;
    state.stack_sample_skel = stack_sample_skel;
    stack_sample_skel = NULL;
    state.max_threads = msg.body.req_setup.max_threads;

    struct received_message_with_ancdata res = { 0 };
    res.body.type = PERF_HELPER_MSG_RES_SETUP;
    res.fd_count = 2;
    res.fds[0] = state.perf_group_fd;
    res.fds[1] = bpf_map__fd(state.stack_sample_skel->maps.events);
    r = write_socket_message(res);
    if (r == -1) {
        ret = -1;
        goto out;
    }

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
handle_message_newthread(struct received_message_with_ancdata msg)
{
    int ret = 0;
    int thread_pidfd = -1;
    int perf_fd = -1;
    struct bpf_link *stack_sample_link = NULL;

    if (msg.fd_count != 1) {
        snprintf(error_message, sizeof(error_message),
                 "received wrong number of FDs (got %zu)", msg.fd_count);
        ret = -1;
        goto out;
    }
    thread_pidfd = msg.fds[0];

    /* validate that the pidfd == the pid we were given */
    pid_t thread_pid = msg.body.req_newthread.thread_pid;
    if (validate_pidfd_pid_matches(thread_pidfd, thread_pid) == -1) {
        ret = -1;
        goto out;
    }

    /* verify that this thread belongs to the same process as we're connected to */
    pid_t thread_tgid;
    if (get_thread_tgid(thread_pid, &thread_tgid) == -1) {
        ret = -1;
        goto out;
    }

    if (thread_tgid != state.caller_creds.pid) {
        snprintf(error_message, sizeof(error_message),
                 "thread belongs to a different process (%d, expected %d)",
                 thread_tgid, state.caller_creds.pid);
        ret = -1;
        goto out;
    }

    struct perf_event_attr perf_attr = { 0 };
    perf_attr.size = sizeof(struct perf_event_attr);
    perf_attr.type = PERF_TYPE_SOFTWARE;
    perf_attr.config = PERF_COUNT_SW_TASK_CLOCK;
    perf_attr.sample_freq = msg.body.req_newthread.interval_hz;
    perf_attr.freq = 1;
    perf_fd = perf_event_open(&perf_attr, thread_pid, -1, state.perf_group_fd, PERF_FLAG_FD_CLOEXEC);
    if (perf_fd == -1) {
        snprintf(error_message, sizeof(error_message),
                 "perf_event_open(2) for dummy event failed: %s", strerror(errno));
        ret = -1;
        goto out;
    }
    
    stack_sample_link = bpf_program__attach_perf_event(state.stack_sample_skel->progs.stack_sample, perf_fd);
    if (!stack_sample_link) {
        snprintf(error_message, sizeof(error_message),
                 "bpf attach failed: %s", strerror(errno));
        ret = -1;
        goto out;
    }

    struct stack_sample_per_thread_data map_data;
    map_data.pid = thread_pid;
    map_data.ruby_stack_ptr = msg.body.req_newthread.ruby_stack_ptr;
    int r = bpf_map__update_elem(state.stack_sample_skel->maps.thread_pids,
                                 &thread_pid, sizeof(pid_t),
                                 &map_data, sizeof(struct stack_sample_per_thread_data),
                                 0);
    if (r < 0) {
        snprintf(error_message, sizeof(error_message),
                 "failed to update ebpf map: %s", strerror(-r));
        ret = -1;
        goto out;
      }

    /* check for pid re-use */
    if (pidfd_alive(thread_pidfd, thread_pid) == -1) {
        ret = -1;
        goto out;
    }

    /* If we got here, save to */
out:
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
handle_message_endthread(struct received_message_with_ancdata msg)
{
    if (msg.fd_count != 0) {
        snprintf(error_message, sizeof(error_message),
                 "received wrong number of FDs (got %zu)", msg.fd_count);
        return -1;
    }
    
    return 0;
    
}

static int
handle_message(struct received_message_with_ancdata msg)
{
    switch (msg.body.type) {
      case PERF_HELPER_MSG_REQ_SETUP:
        return handle_message_setup(msg);
      case PERF_HELPER_MSG_REQ_NEWTHREAD:
        return handle_message_newthread(msg);
      case PERF_HELPER_MSG_REQ_ENDTHREAD:
        return handle_message_endthread(msg);
      default:
        snprintf(error_message, sizeof(error_message),
                 "unknown received message type %d", msg.body.type);
        return -1;
    }
}

static void
init_state(void)
{
    memset(&state, 0, sizeof(state));
    state.socket_fd = -1;
    state.caller_pid_fd = -1;
    state.perf_group_fd = -1;
    init_proc_table();
}

static void
cleanup_state(void)
{
    if (state.stack_sample_skel) {
        stack_sample_bpf__destroy(state.stack_sample_skel);
    }
    if (state.perf_group_fd != -1) {
        close(state.perf_group_fd);
    }
    if (state.caller_pid_fd != -1) {
        close(state.caller_pid_fd);
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
    /* Zero out our state structure */
    init_state();

    /* The unix socketpair we listen on needs to be passed in as FD 3 */
    state.socket_fd = SOCKET_FD;
    
    /* This check is not strictly speaking needed, but included in the interests of defence
     * in depth. Ensure that the socket we received was actually bound by our parent process.
     * Note that this is not at all a sufficient check on its own because if our parent process
     * had a socket pair that came e.g. from init (pid1), and promptly exited after forking us,
     * we might conclude that our parent (init) owns the socket and all is OK */
    if (validate_socket_peercred_matches_parent() == -1) {
        fprintf(stderr, "%s\n", error_message);
        exit(1);
    }

    while (true) {
        struct received_message_with_ancdata msg;
        int r = read_socket_message(&msg);
        if (r == 0) {
            /* orderly shutdown of the socket */
            cleanup_state();
            exit(0);
        } else if (r == -1) {
            fprintf(stderr, "%s\n", error_message);
            exit(1);
        }
        r = handle_message(msg);
        if (r == -1) {
            fprintf(stderr, "%s\n", error_message);
            exit(1);
        }
    }

/*
    struct perf_event_attr swclock_attr = { 0 };
    swclock_attr.size = sizeof(struct perf_event_attr);
    swclock_attr.type = PERF_TYPE_SOFTWARE;
    swclock_attr.config = PERF_COUNT_SW_TASK_CLOCK;
    swclock_attr.sample_freq = 50;
    swclock_attr.freq = 1;
    swclock_attr.precise_ip = 2;
    swclock_attr.disabled = 1;
    int swclock_fd = perf_event_open(&swclock_attr, profile_pid, -1, -1, PERF_FLAG_FD_CLOEXEC);
 
    struct stack_sample_bpf *stack_sample_skel = stack_sample_bpf__open_and_load();
    if (!stack_sample_skel) {
        fprintf(stderr, "stack_sample_bpf__open_and_load() failed: %s\n", strerror(errno));
        exit(1);
    }

    struct bpf_link *stack_sample_link =
        bpf_program__attach_perf_event(stack_sample_skel->progs.stack_sample, swclock_fd);
    if (!stack_sample_link) {
        fprintf(stderr, "bpf_program__attach_pref_event() failed: %s\n", strerror(errno));
        exit(1);
    }

    int fds[NUM_RESPONSE_FDS] = {
        swclock_fd,
        bpf_map__fd(stack_sample_skel->maps.events),
        bpf_link__fd(stack_sample_link),
        bpf_program__fd(stack_sample_skel->progs.stack_sample),
    };

    send_response_msg(fds);
 */   
    return 0;
}
