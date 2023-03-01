#include "ruby/internal/config.h"

#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include <sys/mman.h>

#include "perf_trampoline.h"
#include "ruby.h"
#include "vm_core.h"

#if defined(HAVE_MMAP) && defined(HAVE_SYSCONF) && defined(HAVE_FTRUNCATE) && defined(HAVE_FALLOCATE)
#   define PERF_TRAMPOLINE_SUPPORTED_SYSTEM
#endif

#if defined(__x86_64__)
#   define PERF_TRAMPOLINE_SUPPORTED_ARCH
#   define TRAMPOLINE_TARGET_OFFSET 19
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
#elif defined(__aarch64__)
#   define PERF_TRAMPOLINE_SUPPORTED_ARCH
#   define TRAMPOLINE_TARGET_OFFSET 24
    typedef struct { char b[32]; } trampoline_bytes_t;
    char trampoline_bytes[32] = {
        /* stp	x29, x30, [sp, #-16]! */
        0xfd, 0x7b, 0xbf, 0xa9,
        /* mov	x29, sp */
        0xfd, 0x03, 0x00, 0x91,
        /* ldr	x3, 18 <trampoline_end> */
        0x83, 0x00, 0x00, 0x58,
        /* blr x3 */
        0x60, 0x00, 0x3f, 0xd6,
        /* ldp	x29, x30, [sp], #16 */
        0xfd, 0x7b, 0xc1, 0xa8,
        /* ret */
        0xc0, 0x03, 0x5f, 0xd6,
        /* The 8-byte address of the function to jump to. */
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00
    };
#endif

#if defined(PERF_TRAMPOLINE_SUPPORTED_SYSTEM) && defined(PERF_TRAMPOLINE_SUPPORTED_ARCH)


/* The "bitmap tree" is the data structure used by the perf_trampoline_allocator to keep track
 * of what slots in its mmaped region have a trampoline for a currently-live function, and what
 * slots are currently free. By doing this, we can make sure that when a Ruby function gets
 * GC'd, we're able to re-use the memory region it was using for its trampoline for a different
 * function.
 *
 * The data structure has a fixed capacity decided at initialization time. It's a tree of bitmaps;
 * at the lowest level of the tree, each bit represents one "slot" - an integer from 0 to the max
 * tree capacity. If the slot is occupied, the bit is set; otherwise, the bit is unset. At higher
 * levels of the tree, each bit represents one uint64_t from the level below. If the bit is set,
 * that means _every_ b is set, and there are no free slots in this region of the tree. If the bit
 * is unset, there is at least one free slot below it in the tree.
 *
 * The tree supports two operations: take_slot and free_slot.
 *
 * take_slot will find a free slot, and set its corresponding bit. It begins at the root of the
 * tree, and looks for the leftmost unset bit in that uint64_t. It uses the index of that bit as
 * the index of the uint64_t to look up at the next lowest level, and repeats the process. Once
 * it gets to the bottom of the tree, the unset bit found is set and its index relative to the
 * beginning of the lowest level of the tree is the found "slot".
 *
 * Then, it walks back up the tree following the same path it traversed downwards. At each level,
 * if all bits in the uint64_t below a bit are set, then the bit is set.
 *
 * The free_slot operation works by looking up the provided slot at the lowest level of the tree,
 * and unsetting that bit. Then, we walk back up to the root, ensuring at each level the bit is
 * unset (since there is now a free slot in this part of the tree).
 *
 * As an optimisation, the tree is "jagged". If the capacity of the tree is not an exact power of
 * 64, we don't actually allocate memory for bitmaps where there would be no valid slot anyway.
 *
 * Both take_slot and free_slot are O(log N), where N is the capacity of the tree.
 */
struct bitmap_tree {
    uint64_t *elements;
    long element_count;
    long capacity;
    long depth;
    struct bitmap_tree_level {
        long offset;
        long len;
        long valid_bits;
    } *levels;
};

static inline uint64_t
log2_floor(uint64_t n)
{
    return 64ul - __builtin_clzl(n) - 1ul;
}

static inline uint64_t
log2_ceil(uint64_t n)
{
    return log2_floor(n - 1ul) + 1ul;
}

static inline uint64_t
div_ceil(uint64_t a, uint64_t b)
{
    return (a / b) + ((a % b) ? 1ul : 0);
}

static inline uint64_t
pow64n(uint64_t n)
{
    return 1ul << (6ul * n);
}

static void
bitmap_tree_initialize(struct bitmap_tree *tree, long capa)
{
    /* n.b. log2 / 6 is a log64 */
    tree->capacity = capa;
    tree->depth = (long)div_ceil(log2_ceil(tree->capacity), 6);
    tree->levels = calloc(tree->depth, sizeof(struct bitmap_tree_level));
    tree->element_count = 0;
    for (long i = 0; i < tree->depth; i++) {
        struct bitmap_tree_level *level = &tree->levels[i];
        level->offset = tree->element_count;
        long inverse_depth = tree->depth - i - 1;
        long slots_represented_by_each_bit = pow64n(inverse_depth);
        level->valid_bits = div_ceil(tree->capacity, slots_represented_by_each_bit);
        level->len = div_ceil(level->valid_bits, 64);
        tree->element_count += level->len;
    }
    tree->elements = calloc(tree->element_count, sizeof(uint64_t));

    /* Mark the bits in the bitmap that don't correspond to any actual slot */
    for (long i = 0; i < tree->depth; i++) {
        struct bitmap_tree_level *level = &tree->levels[i];
        long num_rightmost_bits_to_set = (level->len * 64) - level->valid_bits;
        if (num_rightmost_bits_to_set != 0) {
            uint64_t mask = UINT64_MAX >> (64ul - num_rightmost_bits_to_set);
            mask = mask << (64ul - num_rightmost_bits_to_set);
            long last_element_index = level->offset + level-> len - 1ul;
            tree->elements[last_element_index] |= mask;
        }
    }
}

static void
bitmap_tree_destroy(struct bitmap_tree *tree)
{
    free(tree->levels);
    free(tree->elements);
}

static long
bitmap_tree_take_slot(struct bitmap_tree *tree)
{
    long slot_at_this_level = 0;
    long bit_path[tree->depth];
    /* Traverse down looking for a free slot */
    for (long i = 0; i < tree->depth; i++) {
      struct bitmap_tree_level *level = &tree->levels[i];
      long bitmap_index = level->offset + slot_at_this_level;
      uint64_t bitmap = tree->elements[bitmap_index];
      if (bitmap == UINT64_MAX) {
        /* This means the bitmap tree is full */
        return -1;
      }
      long bit = __builtin_ctzl(~bitmap);
      slot_at_this_level = slot_at_this_level * 64 + bit;
      bit_path[i] = slot_at_this_level;
    }
    /* Now traverse back up marking the selected bits as full if applicable */
    for (long i = tree->depth - 1; i >= 0; i--) {
      struct bitmap_tree_level *level = &tree->levels[i];
      long selected_bitmap = bit_path[i] / 64;
      long selected_bit = bit_path[i] % 64;
      uint64_t *bitmap = &tree->elements[level->offset + selected_bitmap];
      *bitmap |= (1ul << selected_bit);
      if (*bitmap != UINT64_MAX) {
        /* If a bitmap is not full, don't continue traversing upwards and marking */
        break;
      }
    }
    return bit_path[tree->depth- 1];
}

static void
bitmap_tree_free_slot(struct bitmap_tree *tree, long slot)
{
    long bit_at_this_level = slot;
    for (long i = tree->depth - 1; i >= 0; i--) {
        struct bitmap_tree_level *level = &tree->levels[i];
        long selected_bitmap = bit_at_this_level / 64;
        long selected_bit = bit_at_this_level % 64;
        uint64_t *bitmap = &tree->elements[level->offset + selected_bitmap];
        bool was_full = (*bitmap == UINT64_MAX);
        *bitmap &= ~(1ul << selected_bit);
        if (!was_full) {
            /* early exit; no need to keep looking up if we weren't full, because the level up
             * would be unset anyway */
            break;
        }
        bit_at_this_level = selected_bitmap;
    }
}

static long
bitmap_tree_count_in_range(struct bitmap_tree *tree, long range_start, long range_end)
{
    if (range_end > tree->capacity) {
        range_end = tree->capacity;
    }
    long ret = 0;
    long ix_start = range_start / 64;
    long ix_end = div_ceil(range_end, 64);
    long start_rem = range_start % 64;
    long end_rem = range_end % 64;
    for (long i = ix_start; i < ix_end; i++) {
        uint64_t mask = UINT64_MAX;
        if (i == ix_start && start_rem != 0) {
            mask &= ~(UINT64_MAX << start_rem);
        }
        if (i == (ix_end - 1) && end_rem != 0) {
            mask &= ~(UINT64_MAX >> end_rem);
        }
        struct bitmap_tree_level *level = &tree->levels[tree->depth - 1];
        uint64_t bitmap = tree->elements[level->offset + i];
        ret += __builtin_popcountl(bitmap & mask);
    }
    return ret;
};

/* The trampoline allocator itself */

struct perf_trampoline_allocator {
    bool initialized;
    bool have_warned_about_exhaustion;
    bool disable_w_x;
    int backing_fd;
    trampoline_bytes_t *trampoline_slots_w;
    trampoline_bytes_t *trampoline_slots_x;
    int page_size;
    long trampoline_slots_count;
    size_t trampoline_slots_len;
    struct bitmap_tree slot_tree;
};

struct perf_trampoline_allocator proc_allocator = { 0 };

static void
destroy_allocator(struct perf_trampoline_allocator *al)
{
    bitmap_tree_destroy(&al->slot_tree);
    if (al->trampoline_slots_w != MAP_FAILED) {
        munmap(al->trampoline_slots_w, al->trampoline_slots_len);
    }
    if (al->trampoline_slots_x != MAP_FAILED) {
        munmap(al->trampoline_slots_x, al->trampoline_slots_len);
    }
    if (al->backing_fd != -1) {
        close(al->backing_fd);
    }
}

static void
open_mem_file(const char *name_stem, int *fd)
{
#ifdef HAVE_MEMFD_CREATE
    *fd = memfd_create(name_stem, MFD_CLOEXEC);
    if (*fd != -1) {
        return;
    } else if (errno != ENOSYS) {
        rb_sys_fail("memfd_create(2)");
    }
    /* if ENOSYS, try one of the methods below. */
#endif

    /* append .XXXXXX to the name_stem to make it a valid mkstemp template */
    size_t tempfile_name_len = strlen(name_stem) + 8;
    char *tempfile_name = alloca(tempfile_name_len);
    snprintf(tempfile_name, tempfile_name_len, "%s.XXXXXX", name_stem);
    bool need_to_cloexec;
#if defined(HAVE_MKOSTEMP)
    *fd = mkostemp(tempfile_name, O_CLOEXEC);
    need_to_cloexec = false;
#elif defined(HAVE_MKSTEMP)
    *fd = mkstemp(tempfile_name);
    need_to_cloexec = true;
#else
    rb_raise(rb_eStandardError, "no memfd_create(2) or mkstemp(3) on this system")
#endif

    if (*fd == -1) {
        rb_sys_fail("mkstemp(3)");
    }
    if (need_to_cloexec) {
        int flags = fcntl(*fd, F_GETFD);
        if (flags == -1) {
            rb_sys_fail("fcntl(2) F_GETFD");
        }
        int r = fcntl(*fd, F_SETFD, flags | FD_CLOEXEC);
        if (r == -1) {
            rb_sys_fail("fcntl(2) F_SETFD");
        }
    }
    int r = unlink(tempfile_name);
    if (r == -1) {
        rb_sys_fail("unlink(2)");
    }
}


static VALUE
init_allocator_i(VALUE vargs)
{
    int r;
    struct perf_trampoline_allocator *al = (struct perf_trampoline_allocator *)vargs;

    al->initialized = false;
    al->backing_fd = -1;
    al->trampoline_slots_w = MAP_FAILED;
    al->trampoline_slots_x = MAP_FAILED;    
    al->trampoline_slots_len = 0;
    al->page_size = -1;
    memset(&al->slot_tree, 0, sizeof(al->slot_tree));

    /* Create the file descriptor which will back the perf trampoline mappings */
    open_mem_file("perf_trampoline", &al->backing_fd);

    /* size the backing fd */
    al->trampoline_slots_len = al->trampoline_slots_count * sizeof(trampoline_bytes_t);
    r = ftruncate(al->backing_fd, al->trampoline_slots_len);
    if (r == -1) {
        rb_sys_fail("ftruncate(2)");
    }

    /* Create the memory mappings themselves */
    if (al->disable_w_x) {
        al->trampoline_slots_w = mmap(NULL, al->trampoline_slots_len, PROT_READ | PROT_WRITE | PROT_EXEC,
                                      MAP_PRIVATE, al->backing_fd, 0);
        if (al->trampoline_slots_w == MAP_FAILED) {
            rb_sys_fail("mmap(2) (WX mapping)");
        }
        al->trampoline_slots_x = al->trampoline_slots_w;
    } else {
        al->trampoline_slots_w = mmap(NULL, al->trampoline_slots_len, PROT_READ | PROT_WRITE,
                                      MAP_SHARED, al->backing_fd, 0);
        if (al->trampoline_slots_w == MAP_FAILED) {
            rb_sys_fail("mmap(2) (writable mapping)");
        }
        al->trampoline_slots_x = mmap(NULL, al->trampoline_slots_len, PROT_READ | PROT_EXEC,
                                      MAP_SHARED, al->backing_fd, 0);
        if (al->trampoline_slots_x == MAP_FAILED) {
            rb_sys_fail("mmap(2) (executable mapping)");
        }
    }

    /* Setup the bitmap tree we will use to work out where free slots are located */
    bitmap_tree_initialize(&al->slot_tree, al->trampoline_slots_count);

    al->page_size = sysconf(_SC_PAGESIZE);
    if (al->page_size == -1) {
        rb_raise(rb_eStandardError, "could not get page size from sysconf(3)");
    }

    al->initialized = true;
    return Qnil;
}

static perf_trampoline_t
perf_trampoline_allocate_i(struct perf_trampoline_allocator *al, void *trampoline_target)
{
    long slot = bitmap_tree_take_slot(&al->slot_tree);
    if (slot == -1) {
        return 0;
    }
    trampoline_bytes_t *trampoline = &al->trampoline_slots_w[slot];
    memcpy(trampoline->b, trampoline_bytes, sizeof(trampoline_bytes_t));
    memcpy(trampoline->b + TRAMPOLINE_TARGET_OFFSET, &trampoline_target, sizeof(void *));
    __sync_synchronize();
    perf_trampoline_t executable_trampoline = (perf_trampoline_t)&al->trampoline_slots_x[slot];
    __clear_cache((char *)executable_trampoline, ((char *)executable_trampoline) + sizeof(perf_trampoline_t));
    return executable_trampoline;
}

void
perf_trampoline_free_i(struct perf_trampoline_allocator *al, perf_trampoline_t trampoline)
{
    long slot = (((char*)trampoline) - ((char *)&al->trampoline_slots_x[0])) / sizeof(trampoline_bytes_t);
    bitmap_tree_free_slot(&al->slot_tree, slot);
    size_t first_slot_in_page = slot / al->page_size;
    if (bitmap_tree_count_in_range(&al->slot_tree, first_slot_in_page, first_slot_in_page + al->page_size) == 0) {
        /* Page is now unused, can free it. */
        int r = fallocate(al->backing_fd, FALLOC_FL_PUNCH_HOLE | FALLOC_FL_KEEP_SIZE,
                          first_slot_in_page * sizeof(trampoline_bytes_t),
                          first_slot_in_page * sizeof(trampoline_bytes_t) + al->page_size);
        if (r == -1) {
            rb_warning("failed to free page trampoline page with fallocate: errno %d\n", errno);
        }
    }
    __sync_synchronize();
}


void
rb_perf_trampoline_initialize(void)
{
    int state;
    proc_allocator.trampoline_slots_count = 1024 * 1024 * 10;
    proc_allocator.disable_w_x = true;
    rb_protect(init_allocator_i, (VALUE)&proc_allocator, &state);
    if (state) {
        VALUE err = rb_errinfo();
        rb_warn("failed to configure perf trampolines: %"PRIsVALUE"; they will not be used.", err);
        destroy_allocator(&proc_allocator);
        proc_allocator = (struct perf_trampoline_allocator){ 0 };
        rb_set_errinfo(Qnil);
    }
}

perf_trampoline_t
rb_perf_trampoline_allocate(void *trampoline_target)
{
    if (!proc_allocator.initialized) {
        return 0;
    }
    perf_trampoline_t tramp = perf_trampoline_allocate_i(&proc_allocator, trampoline_target);
    if (!tramp) {
        if (!proc_allocator.have_warned_about_exhaustion) {
            rb_warning("ran out of perf_trampoline slots! perf-based profiling might miss frames.");
            proc_allocator.have_warned_about_exhaustion = true;
        }
    }
    return tramp;
}

void
rb_perf_trampoline_free(perf_trampoline_t trampoline)
{
    if (!proc_allocator.initialized) {
        return;
    }
    perf_trampoline_free_i(&proc_allocator, trampoline);
}


bool
rb_perf_trampoline_enabled_p(void)
{
    return proc_allocator.initialized;
}

void
rb_perf_trampoline_deinitialize(void)
{
    if (proc_allocator.initialized) {
        destroy_allocator(&proc_allocator);
        proc_allocator = (struct perf_trampoline_allocator){ 0 };
    }
}

/**** DEBUGGING HACKS ****/

static void
bitmap_tree_rb_free(void *ptr)
{
    bitmap_tree_destroy((struct bitmap_tree *)ptr);
    free(ptr);
}

static const rb_data_type_t bitmap_tree_rb_type = {
    "bitmap_tree",
    {
        .dmark = NULL,
        .dfree = bitmap_tree_rb_free,
        .dsize = NULL,
        .dcompact = NULL,
    },
    0, 0
};

static VALUE
bitmap_tree_rb_alloc(VALUE klass)
{
    struct bitmap_tree *tree = calloc(1, sizeof(struct bitmap_tree));
    memset(tree, 0, sizeof(struct bitmap_tree));
    return TypedData_Wrap_Struct(klass, &bitmap_tree_rb_type, tree);
}

static VALUE
bitmap_tree_rb_initialize(VALUE self, VALUE capa)
{
    struct bitmap_tree *tree;
    TypedData_Get_Struct(self, struct bitmap_tree, &bitmap_tree_rb_type, tree);
    bitmap_tree_initialize(tree, RB_NUM2LONG(capa));
    return Qnil;
}

static VALUE
bitmap_tree_rb_take_slot(VALUE self)
{
    struct bitmap_tree *tree;
    TypedData_Get_Struct(self, struct bitmap_tree, &bitmap_tree_rb_type, tree);
    long ret = bitmap_tree_take_slot(tree);
    return RB_LONG2NUM(ret);
}

static VALUE
bitmap_tree_rb_free_slot(VALUE self, VALUE slot)
{
    struct bitmap_tree *tree;
    TypedData_Get_Struct(self, struct bitmap_tree, &bitmap_tree_rb_type, tree);
    bitmap_tree_free_slot(tree, RB_NUM2LONG(slot));
    return Qnil;
}

static VALUE
bitmap_tree_rb_count_in_range(VALUE self, VALUE range_start, VALUE range_end)
{
    struct bitmap_tree *tree;
    TypedData_Get_Struct(self, struct bitmap_tree, &bitmap_tree_rb_type, tree);
    long ret = bitmap_tree_count_in_range(tree, RB_NUM2LONG(range_start), RB_NUM2LONG(range_end));
    return RB_LONG2NUM(ret);
}

void
Init_perf_trampoline_debug(void)
{
    VALUE cBitmapTree = rb_define_class_under(rb_cObject, "BitmapTree", rb_cObject);
    rb_define_alloc_func(cBitmapTree, bitmap_tree_rb_alloc);
    rb_define_method(cBitmapTree, "initialize", bitmap_tree_rb_initialize, 1);
    rb_define_method(cBitmapTree, "take_slot", bitmap_tree_rb_take_slot, 0);
    rb_define_method(cBitmapTree, "free_slot", bitmap_tree_rb_free_slot, 1);
    rb_define_method(cBitmapTree, "count_in_range", bitmap_tree_rb_count_in_range, 2);
}

#else

void
rb_perf_trampoline_initialize(void)
{
    rb_warn("perf trampolines are not available on this system; they will not be used.");
}

perf_trampoline_t
rb_perf_trampoline_allocate(void *trampoline_target)
{
    return 0;
}

void
rb_perf_trampoline_free(perf_trampoline_t *trampoline)
{
}

bool
rb_perf_trampoline_enabled_p(void)
{
    return false;
}

void
rb_perf_trampoline_deinitialize(void)
{
}

#endif