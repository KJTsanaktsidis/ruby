/* n.b. this is included from both the extension and the perf_helper,
 * so no Ruby includes here */
#ifdef RUBY_EXTCONF_H
#include "extconf.h"
#endif

#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>
#include "perf_helper_message.h"

/* Reads a message from the socket. Returns -1 on error, 0 if there is no
 * message to be read (either because the socket is nonblocking, or the
 * remote end is closed), and 1 if a message is returned. */
int
read_perf_helper_message(int socket_fd, struct perf_helper_msg *msg_out,
                          char *errbuf, size_t errbuf_len)
{
    char strerror_buf[256];
    union {
        struct cmsghdr align;
        char buf[
          /* space for a SCM_CREDENTIALS message */
          CMSG_SPACE(sizeof(struct ucred)) +
          /* space for SCM_RIGHTS */
          CMSG_SPACE(MAX_PERF_HELPER_FDS * sizeof(int))
        ];
    } cmsgbuf;
    memset(&cmsgbuf.buf, 0, sizeof(cmsgbuf.buf));

    struct iovec iov;
    iov.iov_base = &msg_out->body;
    iov.iov_len = sizeof(struct perf_helper_msg_body);

    struct msghdr socket_msg;
    socket_msg.msg_iov = &iov;
    socket_msg.msg_iovlen = 1;
    socket_msg.msg_control = cmsgbuf.buf;
    socket_msg.msg_controllen = sizeof(cmsgbuf.buf);
    socket_msg.msg_flags = 0;

    int r;
    while (true) {
        r = recvmsg(socket_fd, &socket_msg, 0);
        if (r == -1 && errno == EINTR) {
            continue;
        }
        if (r == -1 && errno = EWOULDBLOCK) {
            return 0;
        }
        if (r == -1) {
            snprintf(errbuf, errbuf_len,
                     "error reading setup request message: %s",
                     strerror_r(errno, strerror_buf, sizeof(strerror_buf)));
            return -1;
        }
        if (r == 0) {
            return 0;
        }
        break;
    }


    if (r < (int)sizeof(struct perf_helper_msg)) {
        snprintf(errbuf, errbuf_len,
                 "received message too small (%d bytes)", r);
        return -1;
    }

    msg_out->ancdata.have_creds = false;
    msg_out->ancdata.fd_count = 0;
    struct cmsghdr *cmsg = CMSG_FIRSTHDR(&socket_msg);
    while (cmsg) {
        if (cmsg->cmsg_level == SOL_SOCKET && cmsg->cmsg_type == SCM_CREDENTIALS) {
            if (cmsg->cmsg_len != sizeof(struct ucred)) {
                snprintf(errbuf, errbuf_len,
                         "size of SCM_CREDENTIALS message wrong (got %zu)", cmsg->cmsg_len);
                return -1;
            }
            memcpy(&msg_out->ancdata.creds, CMSG_DATA(cmsg), cmsg->cmsg_len);
            msg_out->ancdata.have_creds = true;
        } else if (cmsg->cmsg_level == SOL_SOCKET && cmsg->cmsg_type == SCM_RIGHTS) {
            if (cmsg->cmsg_len > MAX_PERF_HELPER_FDS * sizeof(int)) {
                snprintf(errbuf, errbuf_len,
                         "size of SCM_RIGHTS message too high (got %zu)", cmsg->cmsg_len);
                return -1;
            }
            memcpy(msg_out->ancdata.fds, CMSG_DATA(cmsg), cmsg->cmsg_len);
            msg_out->ancdata.fd_count = cmsg->cmsg_len / sizeof(int);            
        }
        
        cmsg = CMSG_NXTHDR(&socket_msg, cmsg);
    }
    return 1;
}

/* Write a message to the socket. Returns 1 if the message was written,
 * -1 on error, or 0 if the message was not written because it would block
 *  & the socket is nonblocking (only the case in the extension - in
 *  perf_helper the socket is in blocking mode) */
int
write_perf_helper_message(int socket_fd, struct perf_helper_msg *msg,
                          char *errbuf, size_t errbuf_len)
{
    char strerror_buf[256];
    union {
        struct cmsghdr align;
        char buf[
          /* space for a SCM_CREDENTIALS message */
          CMSG_SPACE(sizeof(struct ucred)) +
          /* space for SCM_RIGHTS */
          CMSG_SPACE(MAX_PERF_HELPER_FDS * sizeof(int))
        ];
    } cmsgbuf;
    memset(&cmsgbuf.buf, 0, sizeof(cmsgbuf.buf));
    struct iovec iov;
    iov.iov_base = &msg->body;
    iov.iov_len = sizeof(struct perf_helper_msg_body);

    struct msghdr socket_msg;
    socket_msg.msg_iov = &iov;
    socket_msg.msg_iovlen = 1;
    socket_msg.msg_controllen = sizeof(cmsgbuf.buf);
    socket_msg.msg_flags = 0;

    struct cmsghdr *cmsg = CMSG_FIRSTHDR(&socket_msg);

    if (msg->ancdata.have_creds) {
        cmsg->cmsg_level = SOL_SOCKET;
        cmsg->cmsg_type = SCM_CREDENTIALS;
        cmsg->cmsg_len = CMSG_LEN(sizeof(struct ucred));
        memcpy(CMSG_DATA(cmsg), &msg->ancdata.creds, sizeof(struct ucred));
        cmsg = CMSG_NXTHDR(&socket_msg, cmsg);
    }
    if (msg->ancdata.fd_count > 0 && msg->ancdata.fd_count < MAX_PERF_HELPER_FDS) {
        cmsg->cmsg_level = SOL_SOCKET;
        cmsg->cmsg_type = SCM_RIGHTS;
        cmsg->cmsg_len = CMSG_LEN(msg->ancdata.fd_count * sizeof(int));
        memcpy(CMSG_DATA(cmsg), msg->ancdata.fds, cmsg->cmsg_len);
        cmsg = CMSG_NXTHDR(&socket_msg, cmsg);
    }

    int r;
    while (true) {
        r = sendmsg(socket_fd, &socket_msg, 0);
        if (r == -1 && errno == EINTR) {
            continue;
        }
        if (r == -1 && errno == EWOULDBLOCK) {
            return 0;
        }
        if (r == -1) {
            snprintf(errbuf, errbuf_len,
                     "sendmsg(2) failed: %s",
                     strerror_r(errno, strerror_buf, sizeof(strerror_buf)));
            return -1;
        }
        break;
    }

    return 0;
}

