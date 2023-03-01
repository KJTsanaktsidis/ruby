
.align 2
.global rb_perf_trampoline_asm
rb_perf_trampoline_asm:
    # Push the _real_ frame pointer & return address to the stack
    stp	x29, x30, [sp, #-16]!
    # Push a fake frame pointer pointing to the real one, as well
    # as our fake return address
    mov x29, sp
    adr x30, fake_pointer
    stp x29, x30, [sp, #-16]!
    mov x29, sp
    # Call the VM
    bl rb_vm_iseq_trampoline
    # Pop off our fake frame, then the real frame, and return.
    ldp	x29, x30, [sp], #16
    ldp	x29, x30, [sp], #16
    ret


.align 2
.global fake_pointer
fake_pointer:
    nop