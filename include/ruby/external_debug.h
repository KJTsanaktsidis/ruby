#ifndef __EXTERNAL_DEBUG_H
#define __EXTERNAL_DEBUG_H


typedef struct rb_external_debug_frame_struct {
    const char *frame_name;
    long frame_name_len;
    struct rb_external_debug_frame_struct *prev;
} rb_external_debug_frame_t;


typedef struct rb_external_debug_header_struct {
    rb_external_debug_frame_t *current_thread_backtrace;     
} rb_external_debug_header_t;

#endif

