#include "ruby/internal/config.h"

#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include <sys/mman.h>

#include "ccan/list/list.h"
#include "vm_core.h"
#include "vm_callinfo.h"

#define TRAMPOLINE_PAGE_SIZE 4096
#define TRAMPOLINE_TARGET_OFFSET 24
typedef struct { char b[32]; } trampoline_bytes_t;
char trampoline_bytes[32] = {
    // stp	x29, x30, [sp, #-16]
    0xa9, 0x3f, 0x7b, 0xfd,
    // mov	x29, sp
    0x91, 0x00, 0x03, 0xfd,
    // ldr	x3, 18 <trampoline_end>
    0x58, 0x00, 0x00, 0x83,
    // blr x3
    0xd6, 0x3f, 0x00, 0x60,
    // ldp	x29, x30, [sp], #16
    0xa8, 0xc1, 0x7b, 0xfd,
    // ret
    0xd6, 0x5f, 0x03, 0xc0,
    // The 8-byte address of the function to jump to.
    0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00
};

struct perf_trampoline_page {
    unsigned long bitmaps[2];
    char padding[16];
    trampoline_bytes_t trampoline_slots[127];
};

static_assert(sizeof(struct perf_trampoline_page) == TRAMPOLINE_PAGE_SIZE);

struct perf_trampoline_page_group {
    struct ccan_list_node ll_node;
    struct perf_trampoline_page *pages;
    size_t pages_count;
    bool failed_grow;
};

int
init_perf_trampoline_pages(rb_vm_t *vm)
{
    return 0;
}

static int
allocate_trampoline_page(rb_vm_t *vm, struct perf_trampoline_page **page_out)
{
    struct perf_trampoline_page_group *group = NULL;
    ccan_list_for_each(&vm->perf_trampoline_pages.page_groups, group, ll_node) {
        /* We already failed to remap this range, no point trying again. */
        if (group->failed_grow) {
            continue;
        }
        size_t old_len = group->pages_count * TRAMPOLINE_PAGE_SIZE;
        size_t new_len = old_len + TRAMPOLINE_PAGE_SIZE;
        void *r = mremap(group->pages, old_len, new_len, 0);
        if (r != MAP_FAILED) {
            /* The remap succeeded, the new page needs to be zeroed */
            memset(&group->pages[group->pages_count], 0, sizeof(struct perf_trampoline_page));
            *page_out = &group->pages[group->pages_count];
            group->pages_count++;
            return 0;
        }
        group->failed_grow = true;
    }

    /* If we get here, we need to make a new mapping. */
    struct perf_trampoline_page_group *new_group = malloc(sizeof(struct perf_trampoline_page_group));
    if (!new_group) {
        return -1;
    }
    memset(new_group, 0, sizeof(struct perf_trampoline_page_group));
    new_group->pages = mmap(NULL, TRAMPOLINE_PAGE_SIZE,
                            PROT_EXEC | PROT_READ | PROT_WRITE,
                            MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
    if (new_group->pages == MAP_FAILED) {
        free(new_group);
        return -1;
    }
    ccan_list_add_tail(&vm->perf_trampoline_pages.page_groups, &new_group->ll_node);
    *page_out = &new_group->pages[0];
    return 0;
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

static void *
allocate_trampoline(rb_vm_t *vm, vm_call_handler *target)
{
    /* find a free trampoline slot */
    struct perf_trampoline_page_group *group = NULL;
    struct perf_trampoline_page *page = NULL;
    size_t slot = 0;
    ccan_list_for_each_rev(&vm->perf_trampoline_pages.page_groups, group, ll_node) {
        for (size_t i = 0; i < group->pages_count; i++) {
           page = &group->pages[i];
            size_t slot = find_free_slot_from_bitmap(page->bitmaps, sizeof(page->bitmaps));
            if (slot <= sizeof(page->trampoline_slots)) {
                /* yes, there is a free trampoline in here. */
                goto return_slot;
            }
        }
    }

    /* If we got this far we need to allocate. */
    int r = allocate_trampoline_page(vm, &page);
    if (r != 0) {
        return NULL;
    }
    slot = 0;

return_slot:
    mark_slot_used_in_bitmap(slot, page->bitmaps);
    memcpy(((char *)&(page->trampoline_slots[slot])) + TRAMPOLINE_TARGET_OFFSET,
            target, sizeof(target));
    return &page->trampoline_slots[slot];
}