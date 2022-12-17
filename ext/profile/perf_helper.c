#include <errno.h>
#include <linux/perf_event.h>
#include <linux/hw_breakpoint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/un.h>
#include <unistd.h>

#include "perf_helper.h"
#include "stack_sample.skel.h"

#define SOCKET_FD 3
#define NUM_RESPONSE_FDS 4

static struct perf_helper_input
read_input(void)
{
    struct perf_helper_input in = { 0 };
    int r = fread(&in, sizeof(struct perf_helper_input), 1, stdin);
    if (r != 1) {
        /* did not read a whole struct? */
        fprintf(stderr, "could not fread pref_helper_input struct from stdin\n");
        exit(1);
    }
    return in;
}

static struct ucred
get_socket_creds(int fd)
{
    struct ucred creds;
    socklen_t sizeof_ucred = sizeof(struct ucred);
    int r = getsockopt(fd, SOL_SOCKET, SO_PEERCRED, &creds, &sizeof_ucred);
    if (r == -1) {
        fprintf(stderr, "could not get peercred from socket: %s\n", strerror(errno));
        exit(1);
    }
    return creds;
}

static int
perf_event_open(struct perf_event_attr *hw_event, pid_t pid, int cpu,
                int group_fd, unsigned long flags)
{
    int r = syscall(__NR_perf_event_open, hw_event, pid, cpu, group_fd, flags);
    if (r < 0) {
        fprintf(stderr, "perf_event_open(2) failed: %s\n", strerror(errno));
        exit(1);
    }
    return r;
}

static void
send_response_msg(int fds[NUM_RESPONSE_FDS])
{
    union {
        struct cmsghdr align;
        char buf[CMSG_SPACE(NUM_RESPONSE_FDS * sizeof(int))];
    } cmsgbuf;
    char body_buf[1] = "\0";
    struct iovec iov;
    iov.iov_base = &body_buf;
    iov.iov_len = sizeof(body_buf);

    struct msghdr msg;
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;
    msg.msg_control = cmsgbuf.buf;
    msg.msg_controllen = sizeof(cmsgbuf.buf);
    msg.msg_flags = 0;

    struct cmsghdr *cmsg = CMSG_FIRSTHDR(&msg);
    cmsg->cmsg_level = SOL_SOCKET;
    cmsg->cmsg_type = SCM_RIGHTS;
    cmsg->cmsg_len = CMSG_LEN(NUM_RESPONSE_FDS * sizeof(int));
    for (int i = 0; i < NUM_RESPONSE_FDS; i++) {
        ((int *)CMSG_DATA(cmsg))[i] = fds[i];
    }

    int r = sendmsg(SOCKET_FD, &msg, 0);
    if (r == -1) {
        fprintf(stderr, "sendmsg(2) of perf fd failed: %s\n", strerror(errno));
        exit(1);
    }
}

int
main(int argc, char **argv)
{
    struct perf_helper_input req = read_input();
    pid_t profile_pid = get_socket_creds(SOCKET_FD).pid;

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

    stack_sample_skel->bss->ruby_current_vm_ptr = req.ruby_current_vm_ptr;

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
    
    return 0;
}
