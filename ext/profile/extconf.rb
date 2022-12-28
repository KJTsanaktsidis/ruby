# frozen_string_literal: true

require 'mkmf'

$INCFLAGS << ' -I$(topdir) -I$(top_srcdir)'
$VPATH << '$(topdir)' << '$(top_srcdir)'
$defs << '-D_GNU_SOURCE'
$objs = [
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

    perf_helper.o: perf_helper.c stack_sample.skel.h
    \t$(ECHO) compiling $(<)
    \t$(Q) $(CC) $(INCFLAGS) $(CPPFLAGS) $(CFLAGS) -D_GNU_SOURCE $(COUTFLAG)$@ -c $(CSRCFLAG)$<

    $(PERF_HELPER_BIN): perf_helper.o
    \t$(ECHO) linking perf_helper
    \t-$(Q)$(RM) $(@)
    \t$(Q) $(CC) -lbpf -o $@ $^

    vmlinux.h:
    \tbpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h

    %.bpf.o: %.bpf.c vmlinux.h
    \tclang -g -O2 -target bpf #{$INCFLAGS} -c -o $@ $<

    %.skel.h: %.bpf.o
    \tbpftool gen skeleton $< > $@

    all: $(PERF_HELPER_BIN) stack_sample.bpf.o
  MAKEFILE
end
