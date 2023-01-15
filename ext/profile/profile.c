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

#include "profile.h"
#include "perf_helper_proxy.h"
#include "linux.h"
#include "profile_session.h"
#include "stack_sample.bpf.h"

VALUE mProfile;

__attribute__((visibility("default")))
void
Init_profile(void)
{
    mProfile = rb_define_module_under(rb_cObject, "Profile");
    init_perf_helper_proxy();
    init_profile_session();
    init_profile_linux();
}
