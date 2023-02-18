#include "ruby/internal/config.h"

#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include <sys/mman.h>

#include "ccan/list/list.h"
#include "vm_core.h"
#include "vm_callinfo.h"
#include "perf_trampoline.h"

#if __x86_64__

#define TRAMPOLINE_TARGET_OFFSET 19
#define TRAMPOLINES_PER_PAGE 127
#define TRAMPOLINE_PAGE_SIZE 4096
typedef struct { char b[32]; } trampoline_bytes_t;
char trampoline_bytes[32] = {
  /* push %rbp */
  0x55,
  /* mov %rsp,%rbp */
  0x48, 0x89, 0xe5,
  /* mov %rcx, 0x7(%rip) <trampoline_end> */
  0x48, 0x89, 0x0d, 0x07, 0x00, 0x00, 0x00,
  /* call *%rcx */
  0xff, 0xd1,
  /* mov %rbp,%rsp */
  0x48, 0x89, 0xec,
  /* pop %rbp */
  0x5d,
  /* ret */
  0xc3,
  /* The 8-byte address of the function to jump to */
  0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00,
  /* 6 bytes of padding to align the function on a qword boundary */
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};

#elif __aarch64__

#define TRAMPOLINE_TARGET_OFFSET 24
#define TRAMPOLINES_PER_PAGE 127
#define TRAMPOLINE_PAGE_SIZE 4096
typedef struct { char b[32]; } trampoline_bytes_t;
char trampoline_bytes[32] = {
    /* stp	x29, x30, [sp, #-16] */
    0xa9, 0x3f, 0x7b, 0xfd,
    /* mov	x29, sp */
    0x91, 0x00, 0x03, 0xfd,
    /* ldr	x3, 18 <trampoline_end> */
    0x58, 0x00, 0x00, 0x83,
    /* blr x3 */
    0xd6, 0x3f, 0x00, 0x60,
    /* ldp	x29, x30, [sp], #16 */
    0xa8, 0xc1, 0x7b, 0xfd,
    /* ret */
    0xd6, 0x5f, 0x03, 0xc0,
    /* The 8-byte address of the function to jump to. */
    0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00
};

#endif

struct perf_trampoline_page {
    unsigned long bitmaps[2];
    char padding[16];
    trampoline_bytes_t trampoline_slots[TRAMPOLINES_PER_PAGE];
};

static_assert(sizeof(struct perf_trampoline_page) == TRAMPOLINE_PAGE_SIZE,
              "perf_trampoline_page must be page-aligned");


void
Init_perf_trampoline_allocator(rb_vm_t *vm)
{
    return;
}

void
Init_perf_trampoline_debug(void)
{
    
}


static size_t
find_free_slot_from_bitmap(unsigned long *bitmaps, size_t bitmaps_count)
{
    unsigned long carry = 0;
    for (size_t i = 0; i < bitmaps_count; i++) {
        unsigned long inverted = ~bitmaps[i];
        if (inverted != 0) {
            int first_one_pos = __builtin_ctzl(inverted);
            return carry + first_one_pos;
        }
        /* all full. */
        carry += sizeof(unsigned long) * 8;
    }
    return carry;
}

static void
mark_slot_used_in_bitmap(size_t slot, unsigned long *bitmaps)
{
    size_t bitmap_index = slot / (sizeof(unsigned long) * 8);
    size_t bit_index = slot % ((sizeof(unsigned long) * 8));
    bitmaps[bitmap_index] |= (1 << bit_index);
}

