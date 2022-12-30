#include "extconf.h"

#include <ruby.h>

#include "profile.h"
#include "linux.h"

VALUE cProfileLinux;

void
init_profile_linux(void)
{
    cProfileLinux = rb_define_module_under(cProfile, "Linux");
}
