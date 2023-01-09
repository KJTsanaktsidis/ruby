#include "extconf.h"

#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/close_range.h>
#include <linux/sched.h>
#include <ruby.h>
#include <ruby/atomic.h>
#include <ruby/io.h>
#include <sched.h>
#include <sys/mman.h>
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

void init_perf_helper_proxy(void)
{
    cPerfHelperProxy = rb_define_class_under(mProfile, "PerfHelperProxy", rb_cObject);
}
