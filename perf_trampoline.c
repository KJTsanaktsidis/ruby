#include "ruby/internal/config.h"

#include <assert.h>
#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include <sys/mman.h>

#include "ccan/list/list.h"
#include "perf_trampoline.h"
#include "ruby.h"
#include "ruby/internal/error.h"
#include "vm_core.h"
#include "vm_callinfo.h"

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

#define BITS_IN_UNSIGNED_LONG (sizeof(unsigned long) * 8)

struct perf_trampoline_allocator {
    int memfd;
    trampoline_bytes_t *trampoline_slots_w;
    trampoline_bytes_t *trampoline_slots_x;
    long trampoline_slots_count;
    size_t trampoline_slots_len;
    uint64_t *bitmap_tree;
    long bitmap_tree_count;
    size_t bitmap_tree_len;
    long bitmap_tree_depth;
    struct {
        long offset;
        long len;
        long valid_bits;
        long depth;
        long inverse_depth;
    } *bitmap_tree_rows;
};


static inline uint64_t
log2_floor(uint64_t n)
{
    return 64u - __builtin_clzl(n) - 1;
}

static inline uint64_t
log2_ceil(uint64_t n)
{
    return log2_floor(n - 1) + 1;
}

static inline uint64_t
div_ceil(uint64_t a, uint64_t b)
{
    return (a / b) + ((a % b) ? 1 : 0);
}

static inline uint64_t
pow64n(uint64_t n)
{
    return 1 << (6 * n);
}

void
init_allocator(struct perf_trampoline_allocator *allocator, long max_trampolines)
{
    char errmsg[256];

    allocator->memfd = -1;
    allocator->trampoline_slots_w = MAP_FAILED;
    allocator->trampoline_slots_x = MAP_FAILED;
    allocator->trampoline_slots_len = 0;
    allocator->bitmap_tree_rows = NULL;
    allocator->bitmap_tree = NULL;

    /* Create the memory region that will hold the perf trampolines themselves */
    allocator->memfd = memfd_create("perf_trampoline_allocator", MFD_CLOEXEC);
    if (allocator->memfd == -1) {
        snprintf(errmsg, sizeof(errmsg),
                 "failed memfd_create(2) for perf trampoline allocator: %s",
                 strerrorname_np(errno));
        goto error;
    }
    allocator->trampoline_slots_count = max_trampolines;
    allocator->trampoline_slots_len = max_trampolines * sizeof(trampoline_bytes_t);
    int r = ftruncate(allocator->memfd, allocator->trampoline_slots_len);
    if (r == -1) {
        snprintf(errmsg, sizeof(errmsg),
                 "failed ftruncate(2) for perf trampoline allocator: %s",
                 strerrorname_np(errno));
        goto error;
    }
    allocator->trampoline_slots_w = mmap(NULL, allocator->trampoline_slots_len, PROT_READ | PROT_WRITE,
                                         MAP_SHARED, allocator->memfd, 0);
    if (allocator->trampoline_slots_w == MAP_FAILED) {
        snprintf(errmsg, sizeof(errmsg),
                 "failed mmap(2) for perf trampoline allocator writable mapping: %s",
                 strerrorname_np(errno));
        goto error;
    }
    allocator->trampoline_slots_x = mmap(NULL, allocator->trampoline_slots_len, PROT_READ | PROT_EXEC,
                                         MAP_SHARED, allocator->memfd, 0);
    if (allocator->trampoline_slots_x == MAP_FAILED) {
        snprintf(errmsg, sizeof(errmsg),
                 "failed mmap(2) for perf trampoline allocator executable mapping: %s",
                 strerrorname_np(errno));
        goto error;
    }

    /* Setup the bitmap tree we will use to work out where free slots are located */
    allocator->bitmap_tree_depth = (long)log2_ceil(max_trampolines);
    allocator->bitmap_tree_rows = xcalloc(allocator->bitmap_tree_depth, sizeof(allocator->bitmap_tree_rows[0]));
    allocator->bitmap_tree_count = 0;
    for (long i = 0; i < allocator->bitmap_tree_depth; i++) {
        
        allocator->bitmap_tree_rows[i].offset = allocator->bitmap_tree_count;
        allocator->bitmap_tree_rows[i].depth = i;
        allocator->bitmap_tree_rows[i].inverse_depth = allocator->bitmap_tree_depth - i;
        long slots_represented_by_each_bit = pow64n(allocator->bitmap_tree_rows[i].inverse_depth);
        allocator->bitmap_tree_rows[i].valid_bits = div_ceil(allocator->trampoline_slots_count, slots_represented_by_each_bit);
        allocator->bitmap_tree_rows[i].len = div_ceil(allocator->bitmap_tree_rows[i].valid_bits, 64);
        allocator->bitmap_tree_count += allocator->bitmap_tree_rows[i].len;
    }
    allocator->bitmap_tree_len = allocator->bitmap_tree_count * sizeof(uint64_t);
    allocator->bitmap_tree = xcalloc(allocator->bitmap_tree_count, sizeof(uint64_t));

    /* Mark the bits in the bitmap that don't correspond to any actual slot */
    for (long i = 0; i < allocator->bitmap_tree_depth; i++) {
        long num_rightmost_bits_to_set = (allocator->bitmap_tree_rows[i].len * 64) - allocator->bitmap_tree_rows[i].valid_bits;
        uint64_t mask = 0xFFFFFFFFFFFFFFFF >> (64 - num_rightmost_bits_to_set);
        mask = mask << (64 - num_rightmost_bits_to_set);
        allocator->bitmap_tree[allocator->bitmap_tree_rows[i].offset + allocator->bitmap_tree_rows[i].len - 1] |= mask;
    }

    return;
error:
    if (allocator->bitmap_tree) {
        free(allocator->bitmap_tree);
    }
    if (allocator->bitmap_tree_rows) {
        free(allocator->bitmap_tree_rows);
    }
    if (allocator->trampoline_slots_w != MAP_FAILED) {
        munmap(allocator->trampoline_slots_w, allocator->trampoline_slots_len);
    }
    if (allocator->trampoline_slots_x != MAP_FAILED) {
        munmap(allocator->trampoline_slots_x, allocator->trampoline_slots_len);
    }
    if (allocator->memfd != -1) {
        close(allocator->memfd);
    }
    fprintf(stderr, "%s\n", errmsg);
    exit(1);
}

static inline unsigned int 
bitmap_find_free_slot_single(uint64_t bitmap)
{
    unsigned long inverted = ~bitmap;
    if (RB_UNLIKELY(inverted == 0)) {
        return 64;
    } else {
        return (unsigned int)__builtin_ctzl(inverted);
    }
}

static void
bitmap_tree_fixup_intermediates(uint64_t *bitmaps, int tree_depth, int num_entries, int slot)
{
    /* Iteratively compute where the tree row starts for each depth level */
    int tree_row_start = 0;
    for (int i = 0; i < tree_depth; i++) {
        tree_row_start += 1 << (6 * i);
    }

    for (int i = tree_depth - 1; i > 0; i--) {
        tree_row_start -= 1 << (6 * i);
        int parent_tree_row_start = tree_row_start - (1 << (6 * (i - 1)));
        /* this value is 0 at the bottom of the tree, and tree_depth - 1 at the top */
        int this_ix = (slot / 64) + tree_row_start;
        int parent_slot = slot / 64;
        int parent_ix = parent_slot / 64 + parent_tree_row_start;
        int this_bit_in_parent_slot = (slot % 64);

        if (bitmaps[this_ix] == 0xFFFFFFFFFFFFFFFF) {
            /* bit needs to be set in parent slot */
            bitmaps[parent_ix] |= (1 << this_bit_in_parent_slot);
        } else {
            /* bit needs to be unset */
            bitmaps[parent_ix] &= ~(1 << this_bit_in_parent_slot);
        }
    }
}

static int 
bitmap_tree_find_and_take_slot(uint64_t *bitmaps, int tree_depth, int num_entries)
{
    struct bitmap_lookup {
        int bitmap_index;
        int bitmap_bit; 
    };
    struct bitmap_lookup lookup_chain[tree_depth];

    int tree_row_start = 0;
    int last_bitmap_bit = 0;
    for (int i = 0; i < tree_depth; i++) {
        int ix = tree_row_start + last_bitmap_bit;
        lookup_chain[i].bitmap_index = ix;
        lookup_chain[i].bitmap_bit = bitmap_find_free_slot_single(bitmaps[ix]);

        /* This is the same as tree_row_start += 64^i */
        tree_row_start += 1 << (6 * i);
        last_bitmap_bit = lookup_chain[i].bitmap_bit;
    }

    int slot = lookup_chain[tree_depth - 1].bitmap_index * 64 +
                lookup_chain[tree_depth - 1].bitmap_bit;
    if (slot < num_entries) {
        /* The entry is valid, mark it */
        int ix = lookup_chain[tree_depth - 1].bitmap_index;
        bitmaps[ix] |= (1 << lookup_chain[tree_depth - 1].bitmap_bit);

        for (int i = tree_depth - 2; i > 0; i--) {
            if (bitmaps[lookup_chain[i + 1].bitmap_index] == 0xFFFFFFFFFFFFFFFF) {
                /* This bitmap is full, mark it too */
                bitmaps[lookup_chain[i].bitmap_index] |= (1 << lookup_chain[i].bitmap_bit);
            }
        }
    }
    return slot;
}

static unsigned int
bitmap_tree_free_slot(uint64_t *bitmaps, int tree_depth, int slot)
{

    int tree_row_start = 0;
    for (int i = 0; i < tree_depth - 1; i++) {
        tree_row_start += 1 << (6 * i);
    }
    int ix = (slot / 64) + tree_row_start;
    int bit = slot % 64;
    bitmaps[ix] &= ~(1 << bit);

    int last_ix;
    for (int i = tree_depth - 2; i > 0; i--) {
        last_ix = ix;
        tree_row_start -= 1 << (6 * i);
        int inverse_depth = tree_depth - 1 - i;
        int divisor = (1 << 6 * inverse_depth);
        ix = (slot / divisor) + tree_row_start;
        if (bitmaps[last_ix] != 0xFFFFFFFFFFFFFFFF) {
        }
    }
    return 0;
}

static void
bitmap_set_slot(size_t slot, unsigned long *bitmaps)
{
    size_t bitmap_index = slot / (sizeof(unsigned long) * 8);
    size_t bit_index = slot % ((sizeof(unsigned long) * 8));
    bitmaps[bitmap_index] |= (1 << bit_index);
}

static void
bitmap_unset_slot(size_t slot, unsigned long *bitmaps)
{
    size_t bitmap_index = slot / (sizeof(unsigned long) * 8);
    size_t bit_index = slot % ((sizeof(unsigned long) * 8));
    bitmaps[bitmap_index] &= ~(1 << bit_index);
}

void
Init_perf_trampoline_allocator(rb_vm_t *vm)
{
    vm->perf_trampoline_allocator = xcalloc(1, sizeof(struct perf_trampoline_allocator));
    init_allocator(vm->perf_trampoline_allocator, 10 * 1024 * 1024);
    return;
}

/**** DEBUGGING HACKS ****/



static VALUE
dbg_set_slot(VALUE self, VALUE slot, VALUE bytestr)
{

    unsigned long *bitmaps = (unsigned long *)RSTRING_PTR(bytestr);
    bitmap_set_slot(NUM2SIZET(slot), bitmaps); 
    return Qnil;
}


static VALUE
dbg_unset_slot(VALUE self, VALUE slot, VALUE bytestr)
{

    unsigned long *bitmaps = (unsigned long *)RSTRING_PTR(bytestr);
    bitmap_unset_slot(NUM2SIZET(slot), bitmaps); 
    return Qnil;
}
void
Init_perf_trampoline_debug(void)
{
    rb_define_method(rb_mKernel, "_dbg_set_slot", dbg_set_slot, 2);
    rb_define_method(rb_mKernel, "_dbg_unset_slot", dbg_unset_slot, 2);
}
