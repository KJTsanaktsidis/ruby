# frozen_string_literal: true

require 'mkmf'

checking_for checking_message("stack growth direction") do
  link_success = try_link0(<<~PROGRAM)
    #include <stdio.h>
    /* recurse to get rid of inlining */
    static int
    stack_growup_p(volatile int *addr, int n)
    {
        volatile int end;
        if (n > 0)
      return *addr = stack_growup_p(addr, n - 1);
        else
      return (&end > addr);
    }
    int main(int argc, char **argv)
    {
        int x;
        int dir = stack_growup_p(&x, 10);
        if (dir == 1) {
          printf("stack_grow_up\\n");
        } else {
          printf("stack_grow_down\\n");
        }
        return 0;
    }
  PROGRAM
  raise "failed to compile stack growth test program" unless link_success
  begin
    output = %x{./#{CONFTEST}}.chomp
    raise "failed to execute stack growth test program" unless $?.success?
    if output == "stack_grow_up"
      $defs << '-DPROFILE_STACK_GROWS_UP'
    elsif output == "stack_grow_down"
      $defs << '-DPROFILE_STACK_GROWS_DOWN'
    else
      raise "unknown output from stack growth test program: #{output}"
    end
  ensure
    rm_f CONFTEST
  end
end

$INCFLAGS << ' -I$(topdir) -I$(top_srcdir)'
$VPATH << '$(topdir)' << '$(top_srcdir)'
$defs << '-D_GNU_SOURCE'
$objs = [
  "linux.#{$OBJEXT}",
  "perf_helper_message.#{$OBJEXT}",
  "profile.#{$OBJEXT}",
  "profile_session.#{$OBJEXT}",
  "perf_helper_proxy.#{$OBJEXT}"
]

have_library 'bpf'
append_cflags '-fvisibility=hidden'
create_header
create_makefile('profile') do |mk|
  mk << <<~MAKEFILE
    PERF_HELPER_BIN = $(TARGET_SO_DIR)perf_helper

    perf_helper.o: perf_helper.c stack_sample.skel.h perf_helper_message.h
    \t$(ECHO) compiling $(<)
    \t$(Q) $(CC) $(INCFLAGS) $(CPPFLAGS) $(CFLAGS) -D_GNU_SOURCE $(COUTFLAG)$@ -c $(CSRCFLAG)$<

    $(PERF_HELPER_BIN): perf_helper.o perf_helper_message.o
    \t$(ECHO) linking perf_helper
    \t-$(Q)$(RM) $(@)
    \t$(Q) $(CC) -o $@ $^ -lbpf

    vmlinux.h:
    \tbpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h

    %.bpf.o: %.bpf.c vmlinux.h
    \tclang -g -O2 -target bpf #{$INCFLAGS} -c -o $@ $<

    %.skel.h: %.bpf.o
    \tbpftool gen skeleton $< > $@

    all: $(PERF_HELPER_BIN) stack_sample.bpf.o
  MAKEFILE
end
