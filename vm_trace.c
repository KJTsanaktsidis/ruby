/**********************************************************************

  vm_trace.c -

  $Author: ko1 $
  created at: Tue Aug 14 19:37:09 2012

  Copyright (C) 1993-2012 Yukihiro Matsumoto

**********************************************************************/

/*
 * This file include two parts:
 *
 * (1) set_trace_func internal mechanisms
 *     and C level API
 *
 * (2) Ruby level API
 *  (2-1) set_trace_func API
 *  (2-2) TracePoint API (not yet)
 *
 */

#include "eval_intern.h"
#include "internal.h"
#include "internal/class.h"
#include "internal/gc.h"
#include "internal/hash.h"
#include "internal/symbol.h"
#include "internal/thread.h"
#include "iseq.h"
#include "rjit.h"
#include "ruby/atomic.h"
#include "ruby/debug.h"
#include "vm_core.h"
#include "ruby/ractor.h"
#include "yjit.h"

#include "builtin.h"

static VALUE sym_default;

/* (1) trace mechanisms */

typedef struct rb_event_hook_struct {
    rb_event_hook_flag_t hook_flags;
    rb_event_flag_t events;
    rb_event_hook_func_t func;
    VALUE data;
    struct rb_event_hook_struct *next;

    struct {
        rb_thread_t *th;
        unsigned int target_line;
    } filter;
} rb_event_hook_t;

typedef void (*rb_event_hook_raw_arg_func_t)(VALUE data, const rb_trace_arg_t *arg);

#define MAX_EVENT_NUM 32

void
rb_hook_list_mark(rb_hook_list_t *hooks)
{
    rb_event_hook_t *hook = hooks->hooks;

    while (hook) {
        rb_gc_mark(hook->data);
        hook = hook->next;
    }
}

void
rb_hook_list_mark_and_update(rb_hook_list_t *hooks)
{
    rb_event_hook_t *hook = hooks->hooks;

    while (hook) {
        rb_gc_mark_and_move(&hook->data);
        hook = hook->next;
    }
}

static void clean_hooks(const rb_execution_context_t *ec, rb_hook_list_t *list);

void
rb_hook_list_free(rb_hook_list_t *hooks)
{
    hooks->need_clean = true;

    if (hooks->running == 0) {
        clean_hooks(GET_EC(), hooks);
    }
}

/* ruby_vm_event_flags management */

void rb_clear_attr_ccs(void);
void rb_clear_bf_ccs(void);

static void
update_global_event_hook(rb_event_flag_t prev_events, rb_event_flag_t new_events)
{
    rb_event_flag_t new_iseq_events = new_events & ISEQ_TRACE_EVENTS;
    rb_event_flag_t enabled_iseq_events = ruby_vm_event_enabled_global_flags & ISEQ_TRACE_EVENTS;
    bool first_time_iseq_events_p = new_iseq_events & ~enabled_iseq_events;
    bool enable_c_call   = (prev_events & RUBY_EVENT_C_CALL)   == 0 && (new_events & RUBY_EVENT_C_CALL);
    bool enable_c_return = (prev_events & RUBY_EVENT_C_RETURN) == 0 && (new_events & RUBY_EVENT_C_RETURN);
    bool enable_call     = (prev_events & RUBY_EVENT_CALL)     == 0 && (new_events & RUBY_EVENT_CALL);
    bool enable_return   = (prev_events & RUBY_EVENT_RETURN)   == 0 && (new_events & RUBY_EVENT_RETURN);

    // Modify ISEQs or CCs to enable tracing
    if (first_time_iseq_events_p) {
        // write all ISeqs only when new events are added for the first time
        rb_iseq_trace_set_all(new_iseq_events | enabled_iseq_events);
    }
    // if c_call or c_return is activated
    else if (enable_c_call || enable_c_return) {
        rb_clear_attr_ccs();
    }
    else if (enable_call || enable_return) {
        rb_clear_bf_ccs();
    }

    ruby_vm_event_flags = new_events;
    ruby_vm_event_enabled_global_flags |= new_events;
    rb_objspace_set_event_hook(new_events);

    // Invalidate JIT code as needed
    if (first_time_iseq_events_p || enable_c_call || enable_c_return) {
        // Invalidate all code when ISEQs are modified to use trace_* insns above.
        // Also invalidate when enabling c_call or c_return because generated code
        // never fires these events.
        // Internal events fire inside C routines so don't need special handling.
        // Do this after event flags updates so other ractors see updated vm events
        // when they wake up.
        rb_yjit_tracing_invalidate_all();
        rb_rjit_tracing_invalidate_all(new_iseq_events);
    }
}

/* add/remove hooks */

static rb_event_hook_t *
alloc_event_hook(rb_event_hook_func_t func, rb_event_flag_t events, VALUE data, rb_event_hook_flag_t hook_flags)
{
    rb_event_hook_t *hook;

    if ((events & RUBY_INTERNAL_EVENT_MASK) && (events & ~RUBY_INTERNAL_EVENT_MASK)) {
        rb_raise(rb_eTypeError, "Can not specify normal event and internal event simultaneously.");
    }

    hook = ALLOC(rb_event_hook_t);
    hook->hook_flags = hook_flags;
    hook->events = events;
    hook->func = func;
    hook->data = data;

    /* no filters */
    hook->filter.th = NULL;
    hook->filter.target_line = 0;

    return hook;
}

static void
hook_list_connect(VALUE list_owner, rb_hook_list_t *list, rb_event_hook_t *hook, int global_p)
{
    rb_event_flag_t prev_events = list->events;
    hook->next = list->hooks;
    list->hooks = hook;
    list->events |= hook->events;

    if (global_p) {
        /* global hooks are root objects at GC mark. */
        update_global_event_hook(prev_events, list->events);
    }
    else {
        RB_OBJ_WRITTEN(list_owner, Qundef, hook->data);
    }
}

static void
connect_event_hook(const rb_execution_context_t *ec, rb_event_hook_t *hook)
{
    rb_hook_list_t *list = rb_ec_ractor_hooks(ec);
    hook_list_connect(Qundef, list, hook, TRUE);
}

static void
rb_threadptr_add_event_hook(const rb_execution_context_t *ec, rb_thread_t *th,
                            rb_event_hook_func_t func, rb_event_flag_t events, VALUE data, rb_event_hook_flag_t hook_flags)
{
    rb_event_hook_t *hook = alloc_event_hook(func, events, data, hook_flags);
    hook->filter.th = th;
    connect_event_hook(ec, hook);
}

void
rb_thread_add_event_hook(VALUE thval, rb_event_hook_func_t func, rb_event_flag_t events, VALUE data)
{
    rb_threadptr_add_event_hook(GET_EC(), rb_thread_ptr(thval), func, events, data, RUBY_EVENT_HOOK_FLAG_SAFE);
}

void
rb_add_event_hook(rb_event_hook_func_t func, rb_event_flag_t events, VALUE data)
{
    rb_add_event_hook2(func, events, data, RUBY_EVENT_HOOK_FLAG_SAFE);
}

void
rb_thread_add_event_hook2(VALUE thval, rb_event_hook_func_t func, rb_event_flag_t events, VALUE data, rb_event_hook_flag_t hook_flags)
{
    rb_threadptr_add_event_hook(GET_EC(), rb_thread_ptr(thval), func, events, data, hook_flags);
}

void
rb_add_event_hook2(rb_event_hook_func_t func, rb_event_flag_t events, VALUE data, rb_event_hook_flag_t hook_flags)
{
    rb_event_hook_t *hook = alloc_event_hook(func, events, data, hook_flags);
    connect_event_hook(GET_EC(), hook);
}

static void
clean_hooks(const rb_execution_context_t *ec, rb_hook_list_t *list)
{
    rb_event_hook_t *hook, **nextp = &list->hooks;
    rb_event_flag_t prev_events = list->events;

    VM_ASSERT(list->running == 0);
    VM_ASSERT(list->need_clean == true);

    list->events = 0;
    list->need_clean = false;

    while ((hook = *nextp) != 0) {
        if (hook->hook_flags & RUBY_EVENT_HOOK_FLAG_DELETED) {
            *nextp = hook->next;
            xfree(hook);
        }
        else {
            list->events |= hook->events; /* update active events */
            nextp = &hook->next;
        }
    }

    if (list->is_local) {
        if (list->events == 0) {
            /* local events */
            ruby_xfree(list);
        }
    }
    else {
        update_global_event_hook(prev_events, list->events);
    }
}

static void
clean_hooks_check(const rb_execution_context_t *ec, rb_hook_list_t *list)
{
    if (UNLIKELY(list->need_clean)) {
        if (list->running == 0) {
            clean_hooks(ec, list);
        }
    }
}

#define MATCH_ANY_FILTER_TH ((rb_thread_t *)1)

/* if func is 0, then clear all funcs */
static int
remove_event_hook(const rb_execution_context_t *ec, const rb_thread_t *filter_th, rb_event_hook_func_t func, VALUE data)
{
    rb_hook_list_t *list = rb_ec_ractor_hooks(ec);
    int ret = 0;
    rb_event_hook_t *hook = list->hooks;

    while (hook) {
        if (func == 0 || hook->func == func) {
            if (hook->filter.th == filter_th || filter_th == MATCH_ANY_FILTER_TH) {
                if (UNDEF_P(data) || hook->data == data) {
                    hook->hook_flags |= RUBY_EVENT_HOOK_FLAG_DELETED;
                    ret+=1;
                    list->need_clean = true;
                }
            }
        }
        hook = hook->next;
    }

    clean_hooks_check(ec, list);
    return ret;
}

static int
rb_threadptr_remove_event_hook(const rb_execution_context_t *ec, const rb_thread_t *filter_th, rb_event_hook_func_t func, VALUE data)
{
    return remove_event_hook(ec, filter_th, func, data);
}

int
rb_thread_remove_event_hook(VALUE thval, rb_event_hook_func_t func)
{
    return rb_threadptr_remove_event_hook(GET_EC(), rb_thread_ptr(thval), func, Qundef);
}

int
rb_thread_remove_event_hook_with_data(VALUE thval, rb_event_hook_func_t func, VALUE data)
{
    return rb_threadptr_remove_event_hook(GET_EC(), rb_thread_ptr(thval), func, data);
}

int
rb_remove_event_hook(rb_event_hook_func_t func)
{
    return remove_event_hook(GET_EC(), NULL, func, Qundef);
}

int
rb_remove_event_hook_with_data(rb_event_hook_func_t func, VALUE data)
{
    return remove_event_hook(GET_EC(), NULL, func, data);
}

void
rb_ec_clear_current_thread_trace_func(const rb_execution_context_t *ec)
{
    rb_threadptr_remove_event_hook(ec, rb_ec_thread_ptr(ec), 0, Qundef);
}

void
rb_ec_clear_all_trace_func(const rb_execution_context_t *ec)
{
    rb_threadptr_remove_event_hook(ec, MATCH_ANY_FILTER_TH, 0, Qundef);
}

/* invoke hooks */

static void
exec_hooks_body(const rb_execution_context_t *ec, rb_hook_list_t *list, const rb_trace_arg_t *trace_arg)
{
    rb_event_hook_t *hook;

    for (hook = list->hooks; hook; hook = hook->next) {
        if (!(hook->hook_flags & RUBY_EVENT_HOOK_FLAG_DELETED) &&
            (trace_arg->event & hook->events) &&
            (LIKELY(hook->filter.th == 0) || hook->filter.th == rb_ec_thread_ptr(ec)) &&
            (LIKELY(hook->filter.target_line == 0) || (hook->filter.target_line == (unsigned int)rb_vm_get_sourceline(ec->cfp)))) {
            if (!(hook->hook_flags & RUBY_EVENT_HOOK_FLAG_RAW_ARG)) {
                (*hook->func)(trace_arg->event, hook->data, trace_arg->self, trace_arg->id, trace_arg->klass);
            }
            else {
                (*((rb_event_hook_raw_arg_func_t)hook->func))(hook->data, trace_arg);
            }
        }
    }
}

static int
exec_hooks_precheck(const rb_execution_context_t *ec, rb_hook_list_t *list, const rb_trace_arg_t *trace_arg)
{
    if (list->events & trace_arg->event) {
        list->running++;
        return TRUE;
    }
    else {
        return FALSE;
    }
}

static void
exec_hooks_postcheck(const rb_execution_context_t *ec, rb_hook_list_t *list)
{
    list->running--;
    clean_hooks_check(ec, list);
}

static void
exec_hooks_unprotected(const rb_execution_context_t *ec, rb_hook_list_t *list, const rb_trace_arg_t *trace_arg)
{
    if (exec_hooks_precheck(ec, list, trace_arg) == 0) return;
    exec_hooks_body(ec, list, trace_arg);
    exec_hooks_postcheck(ec, list);
}

static int
exec_hooks_protected(rb_execution_context_t *ec, rb_hook_list_t *list, const rb_trace_arg_t *trace_arg)
{
    enum ruby_tag_type state;
    volatile int raised;

    if (exec_hooks_precheck(ec, list, trace_arg) == 0) return 0;

    raised = rb_ec_reset_raised(ec);

    /* TODO: Support !RUBY_EVENT_HOOK_FLAG_SAFE hooks */

    EC_PUSH_TAG(ec);
    if ((state = EC_EXEC_TAG()) == TAG_NONE) {
        exec_hooks_body(ec, list, trace_arg);
    }
    EC_POP_TAG();

    exec_hooks_postcheck(ec, list);

    if (raised) {
        rb_ec_set_raised(ec);
    }

    return state;
}

// pop_p: Whether to pop the frame for the TracePoint when it throws.
void
rb_exec_event_hooks(rb_trace_arg_t *trace_arg, rb_hook_list_t *hooks, int pop_p)
{
    rb_execution_context_t *ec = trace_arg->ec;

    if (UNLIKELY(trace_arg->event & RUBY_INTERNAL_EVENT_MASK)) {
        if (ec->trace_arg && (ec->trace_arg->event & RUBY_INTERNAL_EVENT_MASK)) {
            /* skip hooks because this thread doing INTERNAL_EVENT */
        }
        else {
            rb_trace_arg_t *prev_trace_arg = ec->trace_arg;

            ec->trace_arg = trace_arg;
            /* only global hooks */
            exec_hooks_unprotected(ec, rb_ec_ractor_hooks(ec), trace_arg);
            ec->trace_arg = prev_trace_arg;
        }
    }
    else {
        if (ec->trace_arg == NULL && /* check reentrant */
            trace_arg->self != rb_mRubyVMFrozenCore /* skip special methods. TODO: remove it. */) {
            const VALUE errinfo = ec->errinfo;
            const VALUE old_recursive = ec->local_storage_recursive_hash;
            int state = 0;

            /* setup */
            ec->local_storage_recursive_hash = ec->local_storage_recursive_hash_for_trace;
            ec->errinfo = Qnil;
            ec->trace_arg = trace_arg;

            /* kick hooks */
            if ((state = exec_hooks_protected(ec, hooks, trace_arg)) == TAG_NONE) {
                ec->errinfo = errinfo;
            }

            /* cleanup */
            ec->trace_arg = NULL;
            ec->local_storage_recursive_hash_for_trace = ec->local_storage_recursive_hash;
            ec->local_storage_recursive_hash = old_recursive;

            if (state) {
                if (pop_p) {
                    if (VM_FRAME_FINISHED_P(ec->cfp)) {
                        ec->tag = ec->tag->prev;
                    }
                    rb_vm_pop_frame(ec);
                }
                EC_JUMP_TAG(ec, state);
            }
        }
    }
}

VALUE
rb_suppress_tracing(VALUE (*func)(VALUE), VALUE arg)
{
    volatile int raised;
    volatile VALUE result = Qnil;
    rb_execution_context_t *const ec = GET_EC();
    rb_vm_t *const vm = rb_ec_vm_ptr(ec);
    enum ruby_tag_type state;
    rb_trace_arg_t dummy_trace_arg;
    dummy_trace_arg.event = 0;

    if (!ec->trace_arg) {
        ec->trace_arg = &dummy_trace_arg;
    }

    raised = rb_ec_reset_raised(ec);

    EC_PUSH_TAG(ec);
    if (LIKELY((state = EC_EXEC_TAG()) == TAG_NONE)) {
        result = (*func)(arg);
    }
    else {
        (void)*&vm; /* suppress "clobbered" warning */
    }
    EC_POP_TAG();

    if (raised) {
        rb_ec_reset_raised(ec);
    }

    if (ec->trace_arg == &dummy_trace_arg) {
        ec->trace_arg = NULL;
    }

    if (state) {
#if defined RUBY_USE_SETJMPEX && RUBY_USE_SETJMPEX
        RB_GC_GUARD(result);
#endif
        EC_JUMP_TAG(ec, state);
    }

    return result;
}

static void call_trace_func(rb_event_flag_t, VALUE data, VALUE self, ID id, VALUE klass);

/* (2-1) set_trace_func (old API) */

/*
 * call-seq:
 *    set_trace_func(proc)    -> proc
 *    set_trace_func(nil)     -> nil
 *
 * Establishes _proc_ as the handler for tracing, or disables
 * tracing if the parameter is +nil+.
 *
 * *Note:* this method is obsolete, please use TracePoint instead.
 *
 * _proc_ takes up to six parameters:
 *
 * * an event name string
 * * a filename string
 * * a line number
 * * a method name symbol, or nil
 * * a binding, or nil
 * * the class, module, or nil
 *
 * _proc_ is invoked whenever an event occurs.
 *
 * Events are:
 *
 * <code>"c-call"</code>:: call a C-language routine
 * <code>"c-return"</code>:: return from a C-language routine
 * <code>"call"</code>:: call a Ruby method
 * <code>"class"</code>:: start a class or module definition
 * <code>"end"</code>:: finish a class or module definition
 * <code>"line"</code>:: execute code on a new line
 * <code>"raise"</code>:: raise an exception
 * <code>"return"</code>:: return from a Ruby method
 *
 * Tracing is disabled within the context of _proc_.
 *
 *   class Test
 *     def test
 *       a = 1
 *       b = 2
 *     end
 *   end
 *
 *   set_trace_func proc { |event, file, line, id, binding, class_or_module|
 *     printf "%8s %s:%-2d %16p %14p\n", event, file, line, id, class_or_module
 *   }
 *   t = Test.new
 *   t.test
 *
 * Produces:
 *
 *   c-return prog.rb:8   :set_trace_func         Kernel
 *       line prog.rb:11              nil            nil
 *     c-call prog.rb:11             :new          Class
 *     c-call prog.rb:11      :initialize    BasicObject
 *   c-return prog.rb:11      :initialize    BasicObject
 *   c-return prog.rb:11             :new          Class
 *       line prog.rb:12              nil            nil
 *       call prog.rb:2             :test           Test
 *       line prog.rb:3             :test           Test
 *       line prog.rb:4             :test           Test
 *     return prog.rb:5             :test           Test
 */

static VALUE
set_trace_func(VALUE obj, VALUE trace)
{
    rb_remove_event_hook(call_trace_func);

    if (NIL_P(trace)) {
        return Qnil;
    }

    if (!rb_obj_is_proc(trace)) {
        rb_raise(rb_eTypeError, "trace_func needs to be Proc");
    }

    rb_add_event_hook(call_trace_func, RUBY_EVENT_ALL, trace);
    return trace;
}

static void
thread_add_trace_func(rb_execution_context_t *ec, rb_thread_t *filter_th, VALUE trace)
{
    if (!rb_obj_is_proc(trace)) {
        rb_raise(rb_eTypeError, "trace_func needs to be Proc");
    }

    rb_threadptr_add_event_hook(ec, filter_th, call_trace_func, RUBY_EVENT_ALL, trace, RUBY_EVENT_HOOK_FLAG_SAFE);
}

/*
 *  call-seq:
 *     thr.add_trace_func(proc)    -> proc
 *
 *  Adds _proc_ as a handler for tracing.
 *
 *  See Thread#set_trace_func and Kernel#set_trace_func.
 */

static VALUE
thread_add_trace_func_m(VALUE obj, VALUE trace)
{
    thread_add_trace_func(GET_EC(), rb_thread_ptr(obj), trace);
    return trace;
}

/*
 *  call-seq:
 *     thr.set_trace_func(proc)    -> proc
 *     thr.set_trace_func(nil)     -> nil
 *
 *  Establishes _proc_ on _thr_ as the handler for tracing, or
 *  disables tracing if the parameter is +nil+.
 *
 *  See Kernel#set_trace_func.
 */

static VALUE
thread_set_trace_func_m(VALUE target_thread, VALUE trace)
{
    rb_execution_context_t *ec = GET_EC();
    rb_thread_t *target_th = rb_thread_ptr(target_thread);

    rb_threadptr_remove_event_hook(ec, target_th, call_trace_func, Qundef);

    if (NIL_P(trace)) {
        return Qnil;
    }
    else {
        thread_add_trace_func(ec, target_th, trace);
        return trace;
    }
}

static const char *
get_event_name(rb_event_flag_t event)
{
    switch (event) {
      case RUBY_EVENT_LINE:     return "line";
      case RUBY_EVENT_CLASS:    return "class";
      case RUBY_EVENT_END:      return "end";
      case RUBY_EVENT_CALL:     return "call";
      case RUBY_EVENT_RETURN:	return "return";
      case RUBY_EVENT_C_CALL:	return "c-call";
      case RUBY_EVENT_C_RETURN:	return "c-return";
      case RUBY_EVENT_RAISE:	return "raise";
      default:
        return "unknown";
    }
}

static ID
get_event_id(rb_event_flag_t event)
{
    ID id;

    switch (event) {
#define C(name, NAME) case RUBY_EVENT_##NAME: CONST_ID(id, #name); return id;
        C(line, LINE);
        C(class, CLASS);
        C(end, END);
        C(call, CALL);
        C(return, RETURN);
        C(c_call, C_CALL);
        C(c_return, C_RETURN);
        C(raise, RAISE);
        C(b_call, B_CALL);
        C(b_return, B_RETURN);
        C(thread_begin, THREAD_BEGIN);
        C(thread_end, THREAD_END);
        C(fiber_switch, FIBER_SWITCH);
        C(script_compiled, SCRIPT_COMPILED);
        C(rescue, RESCUE);
#undef C
      default:
        return 0;
    }
}

static void
get_path_and_lineno(const rb_execution_context_t *ec, const rb_control_frame_t *cfp, rb_event_flag_t event, VALUE *pathp, int *linep)
{
    cfp = rb_vm_get_ruby_level_next_cfp(ec, cfp);

    if (cfp) {
        const rb_iseq_t *iseq = cfp->iseq;
        *pathp = rb_iseq_path(iseq);

        if (event & (RUBY_EVENT_CLASS |
                     RUBY_EVENT_CALL  |
                     RUBY_EVENT_B_CALL)) {
            *linep = FIX2INT(rb_iseq_first_lineno(iseq));
        }
        else {
            *linep = rb_vm_get_sourceline(cfp);
        }
    }
    else {
        *pathp = Qnil;
        *linep = 0;
    }
}

static void
call_trace_func(rb_event_flag_t event, VALUE proc, VALUE self, ID id, VALUE klass)
{
    int line;
    VALUE filename;
    VALUE eventname = rb_str_new2(get_event_name(event));
    VALUE argv[6];
    const rb_execution_context_t *ec = GET_EC();

    get_path_and_lineno(ec, ec->cfp, event, &filename, &line);

    if (!klass) {
        rb_ec_frame_method_id_and_class(ec, &id, 0, &klass);
    }

    if (klass) {
        if (RB_TYPE_P(klass, T_ICLASS)) {
            klass = RBASIC(klass)->klass;
        }
        else if (FL_TEST(klass, FL_SINGLETON)) {
            klass = RCLASS_ATTACHED_OBJECT(klass);
        }
    }

    argv[0] = eventname;
    argv[1] = filename;
    argv[2] = INT2FIX(line);
    argv[3] = id ? ID2SYM(id) : Qnil;
    argv[4] = Qnil;
    if (self && (filename != Qnil) &&
        event != RUBY_EVENT_C_CALL &&
        event != RUBY_EVENT_C_RETURN &&
        (VM_FRAME_RUBYFRAME_P(ec->cfp) && imemo_type_p((VALUE)ec->cfp->iseq, imemo_iseq))) {
        argv[4] = rb_binding_new();
    }
    argv[5] = klass ? klass : Qnil;

    rb_proc_call_with_block(proc, 6, argv, Qnil);
}

/* (2-2) TracePoint API */

static VALUE rb_cTracePoint;

typedef struct rb_tp_struct {
    rb_event_flag_t events;
    int tracing; /* bool */
    rb_thread_t *target_th;
    VALUE local_target_set; /* Hash: target ->
                             * Qtrue (if target is iseq) or
                             * Qfalse (if target is bmethod)
                             */
    void (*func)(VALUE tpval, void *data);
    void *data;
    VALUE proc;
    rb_ractor_t *ractor;
    VALUE self;
} rb_tp_t;

static void
tp_mark(void *ptr)
{
    rb_tp_t *tp = ptr;
    rb_gc_mark(tp->proc);
    rb_gc_mark(tp->local_target_set);
    if (tp->target_th) rb_gc_mark(tp->target_th->self);
}

static size_t
tp_memsize(const void *ptr)
{
    return sizeof(rb_tp_t);
}

static const rb_data_type_t tp_data_type = {
    "tracepoint",
    {tp_mark, RUBY_TYPED_DEFAULT_FREE, tp_memsize,},
    0, 0, RUBY_TYPED_FREE_IMMEDIATELY
};

static VALUE
tp_alloc(VALUE klass)
{
    rb_tp_t *tp;
    return TypedData_Make_Struct(klass, rb_tp_t, &tp_data_type, tp);
}

static rb_event_flag_t
symbol2event_flag(VALUE v)
{
    ID id;
    VALUE sym = rb_to_symbol_type(v);
    const rb_event_flag_t RUBY_EVENT_A_CALL =
        RUBY_EVENT_CALL | RUBY_EVENT_B_CALL | RUBY_EVENT_C_CALL;
    const rb_event_flag_t RUBY_EVENT_A_RETURN =
        RUBY_EVENT_RETURN | RUBY_EVENT_B_RETURN | RUBY_EVENT_C_RETURN;

#define C(name, NAME) CONST_ID(id, #name); if (sym == ID2SYM(id)) return RUBY_EVENT_##NAME
    C(line, LINE);
    C(class, CLASS);
    C(end, END);
    C(call, CALL);
    C(return, RETURN);
    C(c_call, C_CALL);
    C(c_return, C_RETURN);
    C(raise, RAISE);
    C(b_call, B_CALL);
    C(b_return, B_RETURN);
    C(thread_begin, THREAD_BEGIN);
    C(thread_end, THREAD_END);
    C(fiber_switch, FIBER_SWITCH);
    C(script_compiled, SCRIPT_COMPILED);
    C(rescue, RESCUE);

    /* joke */
    C(a_call, A_CALL);
    C(a_return, A_RETURN);
#undef C
    rb_raise(rb_eArgError, "unknown event: %"PRIsVALUE, rb_sym2str(sym));
}

static rb_tp_t *
tpptr(VALUE tpval)
{
    rb_tp_t *tp;
    TypedData_Get_Struct(tpval, rb_tp_t, &tp_data_type, tp);
    return tp;
}

static rb_trace_arg_t *
get_trace_arg(void)
{
    rb_trace_arg_t *trace_arg = GET_EC()->trace_arg;
    if (trace_arg == 0) {
        rb_raise(rb_eRuntimeError, "access from outside");
    }
    return trace_arg;
}

struct rb_trace_arg_struct *
rb_tracearg_from_tracepoint(VALUE tpval)
{
    return get_trace_arg();
}

rb_event_flag_t
rb_tracearg_event_flag(rb_trace_arg_t *trace_arg)
{
    return trace_arg->event;
}

VALUE
rb_tracearg_event(rb_trace_arg_t *trace_arg)
{
    return ID2SYM(get_event_id(trace_arg->event));
}

static void
fill_path_and_lineno(rb_trace_arg_t *trace_arg)
{
    if (UNDEF_P(trace_arg->path)) {
        get_path_and_lineno(trace_arg->ec, trace_arg->cfp, trace_arg->event, &trace_arg->path, &trace_arg->lineno);
    }
}

VALUE
rb_tracearg_lineno(rb_trace_arg_t *trace_arg)
{
    fill_path_and_lineno(trace_arg);
    return INT2FIX(trace_arg->lineno);
}
VALUE
rb_tracearg_path(rb_trace_arg_t *trace_arg)
{
    fill_path_and_lineno(trace_arg);
    return trace_arg->path;
}

static void
fill_id_and_klass(rb_trace_arg_t *trace_arg)
{
    if (!trace_arg->klass_solved) {
        if (!trace_arg->klass) {
            rb_vm_control_frame_id_and_class(trace_arg->cfp, &trace_arg->id, &trace_arg->called_id, &trace_arg->klass);
        }

        if (trace_arg->klass) {
            if (RB_TYPE_P(trace_arg->klass, T_ICLASS)) {
                trace_arg->klass = RBASIC(trace_arg->klass)->klass;
            }
        }
        else {
            trace_arg->klass = Qnil;
        }

        trace_arg->klass_solved = 1;
    }
}

VALUE
rb_tracearg_parameters(rb_trace_arg_t *trace_arg)
{
    switch (trace_arg->event) {
      case RUBY_EVENT_CALL:
      case RUBY_EVENT_RETURN:
      case RUBY_EVENT_B_CALL:
      case RUBY_EVENT_B_RETURN: {
        const rb_control_frame_t *cfp = rb_vm_get_ruby_level_next_cfp(trace_arg->ec, trace_arg->cfp);
        if (cfp) {
            int is_proc = 0;
            if (VM_FRAME_TYPE(cfp) == VM_FRAME_MAGIC_BLOCK && !VM_FRAME_LAMBDA_P(cfp)) {
                is_proc = 1;
            }
            return rb_iseq_parameters(cfp->iseq, is_proc);
        }
        break;
      }
      case RUBY_EVENT_C_CALL:
      case RUBY_EVENT_C_RETURN: {
        fill_id_and_klass(trace_arg);
        if (trace_arg->klass && trace_arg->id) {
            const rb_method_entry_t *me;
            VALUE iclass = Qnil;
            me = rb_method_entry_without_refinements(trace_arg->klass, trace_arg->called_id, &iclass);
            return rb_unnamed_parameters(rb_method_entry_arity(me));
        }
        break;
      }
      case RUBY_EVENT_RAISE:
      case RUBY_EVENT_LINE:
      case RUBY_EVENT_CLASS:
      case RUBY_EVENT_END:
      case RUBY_EVENT_SCRIPT_COMPILED:
      case RUBY_EVENT_RESCUE:
        rb_raise(rb_eRuntimeError, "not supported by this event");
        break;
    }
    return Qnil;
}

VALUE
rb_tracearg_method_id(rb_trace_arg_t *trace_arg)
{
    fill_id_and_klass(trace_arg);
    return trace_arg->id ? ID2SYM(trace_arg->id) : Qnil;
}

VALUE
rb_tracearg_callee_id(rb_trace_arg_t *trace_arg)
{
    fill_id_and_klass(trace_arg);
    return trace_arg->called_id ? ID2SYM(trace_arg->called_id) : Qnil;
}

VALUE
rb_tracearg_defined_class(rb_trace_arg_t *trace_arg)
{
    fill_id_and_klass(trace_arg);
    return trace_arg->klass;
}

VALUE
rb_tracearg_binding(rb_trace_arg_t *trace_arg)
{
    rb_control_frame_t *cfp;
    switch (trace_arg->event) {
      case RUBY_EVENT_C_CALL:
      case RUBY_EVENT_C_RETURN:
        return Qnil;
    }
    cfp = rb_vm_get_binding_creatable_next_cfp(trace_arg->ec, trace_arg->cfp);

    if (cfp && imemo_type_p((VALUE)cfp->iseq, imemo_iseq)) {
        return rb_vm_make_binding(trace_arg->ec, cfp);
    }
    else {
        return Qnil;
    }
}

VALUE
rb_tracearg_self(rb_trace_arg_t *trace_arg)
{
    return trace_arg->self;
}

VALUE
rb_tracearg_return_value(rb_trace_arg_t *trace_arg)
{
    if (trace_arg->event & (RUBY_EVENT_RETURN | RUBY_EVENT_C_RETURN | RUBY_EVENT_B_RETURN)) {
        /* ok */
    }
    else {
        rb_raise(rb_eRuntimeError, "not supported by this event");
    }
    if (UNDEF_P(trace_arg->data)) {
        rb_bug("rb_tracearg_return_value: unreachable");
    }
    return trace_arg->data;
}

VALUE
rb_tracearg_raised_exception(rb_trace_arg_t *trace_arg)
{
    if (trace_arg->event & (RUBY_EVENT_RAISE | RUBY_EVENT_RESCUE)) {
        /* ok */
    }
    else {
        rb_raise(rb_eRuntimeError, "not supported by this event");
    }
    if (UNDEF_P(trace_arg->data)) {
        rb_bug("rb_tracearg_raised_exception: unreachable");
    }
    return trace_arg->data;
}

VALUE
rb_tracearg_eval_script(rb_trace_arg_t *trace_arg)
{
    VALUE data = trace_arg->data;

    if (trace_arg->event & (RUBY_EVENT_SCRIPT_COMPILED)) {
        /* ok */
    }
    else {
        rb_raise(rb_eRuntimeError, "not supported by this event");
    }
    if (UNDEF_P(data)) {
        rb_bug("rb_tracearg_raised_exception: unreachable");
    }
    if (rb_obj_is_iseq(data)) {
        return Qnil;
    }
    else {
        VM_ASSERT(RB_TYPE_P(data, T_ARRAY));
        /* [src, iseq] */
        return RARRAY_AREF(data, 0);
    }
}

VALUE
rb_tracearg_instruction_sequence(rb_trace_arg_t *trace_arg)
{
    VALUE data = trace_arg->data;

    if (trace_arg->event & (RUBY_EVENT_SCRIPT_COMPILED)) {
        /* ok */
    }
    else {
        rb_raise(rb_eRuntimeError, "not supported by this event");
    }
    if (UNDEF_P(data)) {
        rb_bug("rb_tracearg_raised_exception: unreachable");
    }

    if (rb_obj_is_iseq(data)) {
        return rb_iseqw_new((const rb_iseq_t *)data);
    }
    else {
        VM_ASSERT(RB_TYPE_P(data, T_ARRAY));
        VM_ASSERT(rb_obj_is_iseq(RARRAY_AREF(data, 1)));

        /* [src, iseq] */
        return rb_iseqw_new((const rb_iseq_t *)RARRAY_AREF(data, 1));
    }
}

VALUE
rb_tracearg_object(rb_trace_arg_t *trace_arg)
{
    if (trace_arg->event & (RUBY_INTERNAL_EVENT_NEWOBJ | RUBY_INTERNAL_EVENT_FREEOBJ)) {
        /* ok */
    }
    else {
        rb_raise(rb_eRuntimeError, "not supported by this event");
    }
    if (UNDEF_P(trace_arg->data)) {
        rb_bug("rb_tracearg_object: unreachable");
    }
    return trace_arg->data;
}

static VALUE
tracepoint_attr_event(rb_execution_context_t *ec, VALUE tpval)
{
    return rb_tracearg_event(get_trace_arg());
}

static VALUE
tracepoint_attr_lineno(rb_execution_context_t *ec, VALUE tpval)
{
    return rb_tracearg_lineno(get_trace_arg());
}
static VALUE
tracepoint_attr_path(rb_execution_context_t *ec, VALUE tpval)
{
    return rb_tracearg_path(get_trace_arg());
}

static VALUE
tracepoint_attr_parameters(rb_execution_context_t *ec, VALUE tpval)
{
    return rb_tracearg_parameters(get_trace_arg());
}

static VALUE
tracepoint_attr_method_id(rb_execution_context_t *ec, VALUE tpval)
{
    return rb_tracearg_method_id(get_trace_arg());
}

static VALUE
tracepoint_attr_callee_id(rb_execution_context_t *ec, VALUE tpval)
{
    return rb_tracearg_callee_id(get_trace_arg());
}

static VALUE
tracepoint_attr_defined_class(rb_execution_context_t *ec, VALUE tpval)
{
    return rb_tracearg_defined_class(get_trace_arg());
}

static VALUE
tracepoint_attr_binding(rb_execution_context_t *ec, VALUE tpval)
{
    return rb_tracearg_binding(get_trace_arg());
}

static VALUE
tracepoint_attr_self(rb_execution_context_t *ec, VALUE tpval)
{
    return rb_tracearg_self(get_trace_arg());
}

static VALUE
tracepoint_attr_return_value(rb_execution_context_t *ec, VALUE tpval)
{
    return rb_tracearg_return_value(get_trace_arg());
}

static VALUE
tracepoint_attr_raised_exception(rb_execution_context_t *ec, VALUE tpval)
{
    return rb_tracearg_raised_exception(get_trace_arg());
}

static VALUE
tracepoint_attr_eval_script(rb_execution_context_t *ec, VALUE tpval)
{
    return rb_tracearg_eval_script(get_trace_arg());
}

static VALUE
tracepoint_attr_instruction_sequence(rb_execution_context_t *ec, VALUE tpval)
{
    return rb_tracearg_instruction_sequence(get_trace_arg());
}

static void
tp_call_trace(VALUE tpval, rb_trace_arg_t *trace_arg)
{
    rb_tp_t *tp = tpptr(tpval);

    if (tp->func) {
        (*tp->func)(tpval, tp->data);
    }
    else {
        if (tp->ractor == NULL || tp->ractor == GET_RACTOR()) {
            rb_proc_call_with_block((VALUE)tp->proc, 1, &tpval, Qnil);
        }
    }
}

VALUE
rb_tracepoint_enable(VALUE tpval)
{
    rb_tp_t *tp;
    tp = tpptr(tpval);

    if (tp->local_target_set != Qfalse) {
        rb_raise(rb_eArgError, "can't nest-enable a targeting TracePoint");
    }

    if (tp->target_th) {
        rb_thread_add_event_hook2(tp->target_th->self, (rb_event_hook_func_t)tp_call_trace, tp->events, tpval,
                                  RUBY_EVENT_HOOK_FLAG_SAFE | RUBY_EVENT_HOOK_FLAG_RAW_ARG);
    }
    else {
        rb_add_event_hook2((rb_event_hook_func_t)tp_call_trace, tp->events, tpval,
                           RUBY_EVENT_HOOK_FLAG_SAFE | RUBY_EVENT_HOOK_FLAG_RAW_ARG);
    }
    tp->tracing = 1;
    return Qundef;
}

static const rb_iseq_t *
iseq_of(VALUE target)
{
    VALUE iseqv = rb_funcall(rb_cISeq, rb_intern("of"), 1, target);
    if (NIL_P(iseqv)) {
        rb_raise(rb_eArgError, "specified target is not supported");
    }
    else {
        return rb_iseqw_to_iseq(iseqv);
    }
}

const rb_method_definition_t *rb_method_def(VALUE method); /* proc.c */

static VALUE
rb_tracepoint_enable_for_target(VALUE tpval, VALUE target, VALUE target_line)
{
    rb_tp_t *tp = tpptr(tpval);
    const rb_iseq_t *iseq = iseq_of(target);
    int n = 0;
    unsigned int line = 0;
    bool target_bmethod = false;

    if (tp->tracing > 0) {
        rb_raise(rb_eArgError, "can't nest-enable a targeting TracePoint");
    }

    if (!NIL_P(target_line)) {
        if ((tp->events & RUBY_EVENT_LINE) == 0) {
            rb_raise(rb_eArgError, "target_line is specified, but line event is not specified");
        }
        else {
            line = NUM2UINT(target_line);
        }
    }

    VM_ASSERT(tp->local_target_set == Qfalse);
    tp->local_target_set = rb_obj_hide(rb_ident_hash_new());

    /* bmethod */
    if (rb_obj_is_method(target)) {
        rb_method_definition_t *def = (rb_method_definition_t *)rb_method_def(target);
        if (def->type == VM_METHOD_TYPE_BMETHOD &&
            (tp->events & (RUBY_EVENT_CALL | RUBY_EVENT_RETURN))) {
            if (def->body.bmethod.hooks == NULL) {
                def->body.bmethod.hooks = ZALLOC(rb_hook_list_t);
            }
            rb_hook_list_connect_tracepoint(target, def->body.bmethod.hooks, tpval, 0);
            rb_hash_aset(tp->local_target_set, target, Qfalse);
            target_bmethod = true;

            n++;
        }
    }

    /* iseq */
    n += rb_iseq_add_local_tracepoint_recursively(iseq, tp->events, tpval, line, target_bmethod);
    rb_hash_aset(tp->local_target_set, (VALUE)iseq, Qtrue);

    if ((tp->events & (RUBY_EVENT_CALL | RUBY_EVENT_RETURN)) &&
        iseq->body->builtin_attrs & BUILTIN_ATTR_SINGLE_NOARG_INLINE) {
        rb_clear_bf_ccs();
    }

    if (n == 0) {
        rb_raise(rb_eArgError, "can not enable any hooks");
    }

    rb_yjit_tracing_invalidate_all();
    rb_rjit_tracing_invalidate_all(tp->events);

    ruby_vm_event_local_num++;

    tp->tracing = 1;

    return Qnil;
}

static int
disable_local_event_iseq_i(VALUE target, VALUE iseq_p, VALUE tpval)
{
    if (iseq_p) {
        rb_iseq_remove_local_tracepoint_recursively((rb_iseq_t *)target, tpval);
    }
    else {
        /* bmethod */
        rb_method_definition_t *def = (rb_method_definition_t *)rb_method_def(target);
        rb_hook_list_t *hooks = def->body.bmethod.hooks;
        VM_ASSERT(hooks != NULL);
        rb_hook_list_remove_tracepoint(hooks, tpval);

        if (hooks->events == 0) {
            rb_hook_list_free(def->body.bmethod.hooks);
            def->body.bmethod.hooks = NULL;
        }
    }
    return ST_CONTINUE;
}

VALUE
rb_tracepoint_disable(VALUE tpval)
{
    rb_tp_t *tp;

    tp = tpptr(tpval);

    if (tp->local_target_set) {
        rb_hash_foreach(tp->local_target_set, disable_local_event_iseq_i, tpval);
        tp->local_target_set = Qfalse;
        ruby_vm_event_local_num--;
    }
    else {
        if (tp->target_th) {
            rb_thread_remove_event_hook_with_data(tp->target_th->self, (rb_event_hook_func_t)tp_call_trace, tpval);
        }
        else {
            rb_remove_event_hook_with_data((rb_event_hook_func_t)tp_call_trace, tpval);
        }
    }
    tp->tracing = 0;
    tp->target_th = NULL;
    return Qundef;
}

void
rb_hook_list_connect_tracepoint(VALUE target, rb_hook_list_t *list, VALUE tpval, unsigned int target_line)
{
    rb_tp_t *tp = tpptr(tpval);
    rb_event_hook_t *hook = alloc_event_hook((rb_event_hook_func_t)tp_call_trace, tp->events, tpval,
                                             RUBY_EVENT_HOOK_FLAG_SAFE | RUBY_EVENT_HOOK_FLAG_RAW_ARG);
    hook->filter.target_line = target_line;
    hook_list_connect(target, list, hook, FALSE);
}

void
rb_hook_list_remove_tracepoint(rb_hook_list_t *list, VALUE tpval)
{
    rb_event_hook_t *hook = list->hooks;
    rb_event_flag_t events = 0;

    while (hook) {
        if (hook->data == tpval) {
            hook->hook_flags |= RUBY_EVENT_HOOK_FLAG_DELETED;
            list->need_clean = true;
        }
        else if ((hook->hook_flags & RUBY_EVENT_HOOK_FLAG_DELETED) == 0) {
            events |= hook->events;
        }
        hook = hook->next;
    }

    list->events = events;
}

static VALUE
tracepoint_enable_m(rb_execution_context_t *ec, VALUE tpval, VALUE target, VALUE target_line, VALUE target_thread)
{
    rb_tp_t *tp = tpptr(tpval);
    int previous_tracing = tp->tracing;

    if (target_thread == sym_default) {
        if (rb_block_given_p() && NIL_P(target) && NIL_P(target_line)) {
            target_thread = rb_thread_current();
        }
        else {
            target_thread = Qnil;
        }
    }

    /* check target_thread */
    if (RTEST(target_thread)) {
        if (tp->target_th) {
            rb_raise(rb_eArgError, "can not override target_thread filter");
        }
        tp->target_th = rb_thread_ptr(target_thread);
    }
    else {
        tp->target_th = NULL;
    }

    if (NIL_P(target)) {
        if (!NIL_P(target_line)) {
            rb_raise(rb_eArgError, "only target_line is specified");
        }
        rb_tracepoint_enable(tpval);
    }
    else {
        rb_tracepoint_enable_for_target(tpval, target, target_line);
    }

    if (rb_block_given_p()) {
        return rb_ensure(rb_yield, Qundef,
                         previous_tracing ? rb_tracepoint_enable : rb_tracepoint_disable,
                         tpval);
    }
    else {
        return RBOOL(previous_tracing);
    }
}

static VALUE
tracepoint_disable_m(rb_execution_context_t *ec, VALUE tpval)
{
    rb_tp_t *tp = tpptr(tpval);
    int previous_tracing = tp->tracing;

    if (rb_block_given_p()) {
        if (tp->local_target_set != Qfalse) {
            rb_raise(rb_eArgError, "can't disable a targeting TracePoint in a block");
        }

        rb_tracepoint_disable(tpval);
        return rb_ensure(rb_yield, Qundef,
                         previous_tracing ? rb_tracepoint_enable : rb_tracepoint_disable,
                         tpval);
    }
    else {
        rb_tracepoint_disable(tpval);
        return RBOOL(previous_tracing);
    }
}

VALUE
rb_tracepoint_enabled_p(VALUE tpval)
{
    rb_tp_t *tp = tpptr(tpval);
    return RBOOL(tp->tracing);
}

static VALUE
tracepoint_enabled_p(rb_execution_context_t *ec, VALUE tpval)
{
    return rb_tracepoint_enabled_p(tpval);
}

static VALUE
tracepoint_new(VALUE klass, rb_thread_t *target_th, rb_event_flag_t events, void (func)(VALUE, void*), void *data, VALUE proc)
{
    VALUE tpval = tp_alloc(klass);
    rb_tp_t *tp;
    TypedData_Get_Struct(tpval, rb_tp_t, &tp_data_type, tp);

    tp->proc = proc;
    tp->ractor = rb_ractor_shareable_p(proc) ? NULL : GET_RACTOR();
    tp->func = func;
    tp->data = data;
    tp->events = events;
    tp->self = tpval;

    return tpval;
}

VALUE
rb_tracepoint_new(VALUE target_thval, rb_event_flag_t events, void (*func)(VALUE, void *), void *data)
{
    rb_thread_t *target_th = NULL;

    if (RTEST(target_thval)) {
        target_th = rb_thread_ptr(target_thval);
        /* TODO: Test it!
         * Warning: This function is not tested.
         */
    }
    return tracepoint_new(rb_cTracePoint, target_th, events, func, data, Qundef);
}

static VALUE
tracepoint_new_s(rb_execution_context_t *ec, VALUE self, VALUE args)
{
    rb_event_flag_t events = 0;
    long i;
    long argc = RARRAY_LEN(args);

    if (argc > 0) {
        for (i=0; i<argc; i++) {
            events |= symbol2event_flag(RARRAY_AREF(args, i));
        }
    }
    else {
        events = RUBY_EVENT_TRACEPOINT_ALL;
    }

    if (!rb_block_given_p()) {
        rb_raise(rb_eArgError, "must be called with a block");
    }

    return tracepoint_new(self, 0, events, 0, 0, rb_block_proc());
}

static VALUE
tracepoint_trace_s(rb_execution_context_t *ec, VALUE self, VALUE args)
{
    VALUE trace = tracepoint_new_s(ec, self, args);
    rb_tracepoint_enable(trace);
    return trace;
}

static VALUE
tracepoint_inspect(rb_execution_context_t *ec, VALUE self)
{
    rb_tp_t *tp = tpptr(self);
    rb_trace_arg_t *trace_arg = GET_EC()->trace_arg;

    if (trace_arg) {
        switch (trace_arg->event) {
          case RUBY_EVENT_LINE:
            {
                VALUE sym = rb_tracearg_method_id(trace_arg);
                if (NIL_P(sym))
                    break;
                return rb_sprintf("#<TracePoint:%"PRIsVALUE" %"PRIsVALUE":%d in `%"PRIsVALUE"'>",
                                  rb_tracearg_event(trace_arg),
                                  rb_tracearg_path(trace_arg),
                                  FIX2INT(rb_tracearg_lineno(trace_arg)),
                                  sym);
            }
          case RUBY_EVENT_CALL:
          case RUBY_EVENT_C_CALL:
          case RUBY_EVENT_RETURN:
          case RUBY_EVENT_C_RETURN:
            return rb_sprintf("#<TracePoint:%"PRIsVALUE" `%"PRIsVALUE"' %"PRIsVALUE":%d>",
                              rb_tracearg_event(trace_arg),
                              rb_tracearg_method_id(trace_arg),
                              rb_tracearg_path(trace_arg),
                              FIX2INT(rb_tracearg_lineno(trace_arg)));
          case RUBY_EVENT_THREAD_BEGIN:
          case RUBY_EVENT_THREAD_END:
            return rb_sprintf("#<TracePoint:%"PRIsVALUE" %"PRIsVALUE">",
                              rb_tracearg_event(trace_arg),
                              rb_tracearg_self(trace_arg));
          default:
            break;
        }
        return rb_sprintf("#<TracePoint:%"PRIsVALUE" %"PRIsVALUE":%d>",
                          rb_tracearg_event(trace_arg),
                          rb_tracearg_path(trace_arg),
                          FIX2INT(rb_tracearg_lineno(trace_arg)));
    }
    else {
        return rb_sprintf("#<TracePoint:%s>", tp->tracing ? "enabled" : "disabled");
    }
}

static void
tracepoint_stat_event_hooks(VALUE hash, VALUE key, rb_event_hook_t *hook)
{
    int active = 0, deleted = 0;

    while (hook) {
        if (hook->hook_flags & RUBY_EVENT_HOOK_FLAG_DELETED) {
            deleted++;
        }
        else {
            active++;
        }
        hook = hook->next;
    }

    rb_hash_aset(hash, key, rb_ary_new3(2, INT2FIX(active), INT2FIX(deleted)));
}

static VALUE
tracepoint_stat_s(rb_execution_context_t *ec, VALUE self)
{
    rb_vm_t *vm = GET_VM();
    VALUE stat = rb_hash_new();

    tracepoint_stat_event_hooks(stat, vm->self, rb_ec_ractor_hooks(ec)->hooks);
    /* TODO: thread local hooks */

    return stat;
}

static VALUE
disallow_reentry(VALUE val)
{
    rb_trace_arg_t *arg = (rb_trace_arg_t *)val;
    rb_execution_context_t *ec = GET_EC();
    if (ec->trace_arg != NULL) rb_bug("should be NULL, but %p", (void *)ec->trace_arg);
    ec->trace_arg = arg;
    return Qnil;
}

static VALUE
tracepoint_allow_reentry(rb_execution_context_t *ec, VALUE self)
{
    const rb_trace_arg_t *arg = ec->trace_arg;
    if (arg == NULL) rb_raise(rb_eRuntimeError, "No need to allow reentrance.");
    ec->trace_arg = NULL;
    return rb_ensure(rb_yield, Qnil, disallow_reentry, (VALUE)arg);
}

#include "trace_point.rbinc"

/* This function is called from inits.c */
void
Init_vm_trace(void)
{
    sym_default = ID2SYM(rb_intern_const("default"));

    /* trace_func */
    rb_define_global_function("set_trace_func", set_trace_func, 1);
    rb_define_method(rb_cThread, "set_trace_func", thread_set_trace_func_m, 1);
    rb_define_method(rb_cThread, "add_trace_func", thread_add_trace_func_m, 1);

    rb_cTracePoint = rb_define_class("TracePoint", rb_cObject);
    rb_undef_alloc_func(rb_cTracePoint);
}

/*
 * rb_postponed_job_queues_t is actually _two_ separate queues.
 *
 * The first queue, the "blocking" queue, is a st_table with potentially
 * duplicate entries implementing a list of func -> data pairs. This queue is
 * protected by a mutex and is accessed by the rb_workqueue* family of
 * functions. Jobs can be enqueued into this queue from arbitrary threads with
 * or without the GVL, but can NOT be enqueued from signal handlers. It's
 * _guaranteed_ that we can enqueue a job into this queue, no matter what (but
 * it might allocate).
 *
 * The second queue, the "async" queue, is a fixed-size, lock-free ringbuffer
 * with a list of rb_pjob_async_t objects. This queue is safe to enqueue into
 * from arbitrary threads and even from inside signal handlers. It will never
 * block; however, if the fixed size buffer is full, it might fail to enqueue
 * the job and return an error.
 *
 * Generally, you should use the blocking queue to enqueue jobs, leaving the
 * async queue for situations where blocking would be unacceptable (such as
 * signal handlers)
 */
#define MAX_POSTPONED_JOB_ASYNC             1024
#define PJOB_ASYNC_FLAG_READY               (1 << 0)
#define PJOB_ASYNC_FLAG_ABANDONED           (1 << 1)
#define PJOB_ASYNC_FLAG_ONCE                (1 << 2)
#define PJOB_ASYNC_MASK_ENQUEUE_INDEX       0x0000FFFF
#define PJOB_ASYNC_SHIFT_ENQUEUE_INDEX      0
#define PJOB_ASYNC_MASK_COUNT               0xFFFF0000
#define PJOB_ASYNC_SHIFT_COUNT              16
typedef struct rb_pjob_async_t {
    rb_postponed_job_func_t func;
    void *data;
    rb_atomic_t flags;
} rb_pjob_async_t;

typedef struct rb_postponed_job_queues {
    struct {
        rb_nativethread_lock_t lock;
        struct st_table *table;
    } blocking;
    struct {
        /* this field stores the enqueue index for where to insert more jobs in
         * the first 16 bits, and the count in the next 16 bits. Stuffing this into
         * the same field allows us to atomically update both the count and position */
        rb_atomic_t enqueue_index_and_count;
        rb_atomic_t dequeue_index;
        /* rb_atomic_t, because size & count should have the same type. count is
         * accessed atomically, but size is only set once. */
        rb_atomic_t ringbuf_size;
        rb_pjob_async_t ringbuf[MAX_POSTPONED_JOB_ASYNC];
    } async;
} rb_postponed_job_queues_t;


void
Init_vm_postponed_job(void)
{
    rb_postponed_job_queues_t *pjq = ruby_xmalloc(sizeof(rb_postponed_job_queues_t));
    rb_nativethread_lock_initialize(&pjq->blocking.lock);
    pjq->blocking.table = st_init_numtable();
    pjq->async.enqueue_index_and_count = 0;
    pjq->async.dequeue_index = 0;
    pjq->async.ringbuf_size = MAX_POSTPONED_JOB_ASYNC;
    memset(pjq->async.ringbuf, 0, sizeof(rb_pjob_async_t) * MAX_POSTPONED_JOB_ASYNC);
    GET_VM()->postponed_job_queues = pjq;
}

// Used for VM memsize reporting. Returns the total size of the postponed job
// queue infrastructure.
size_t
rb_vm_memsize_postponed_job_queues(void)
{
    rb_postponed_job_queues_t *pjq = GET_VM()->postponed_job_queues;
    size_t sz = sizeof(*pjq);
    if (pjq->blocking.table) {
        sz += st_memsize(pjq->blocking.table);
    }
    return sz;
}

static rb_execution_context_t *
get_valid_ec(rb_vm_t *vm)
{
    rb_execution_context_t *ec = rb_current_execution_context(false);
    if (ec == NULL) ec = rb_vm_main_ractor_ec(vm);
    return ec;
}

static inline void
pjob_async_increment_index_with_wrap(rb_postponed_job_queues_t *pjq, rb_atomic_t *index)
{
    (*index)++;
    if (*index == pjq->async.ringbuf_size) {
        *index = 0;
    }
}

static inline void
pjob_async_decrement_index_with_wrap(rb_postponed_job_queues_t *pjq, rb_atomic_t *index)
{
    if (*index == 0) {
        *index = pjq->async.ringbuf_size - 1;
    } else {
        (*index)--;
    }
}

static inline void
pjob_async_decompose_enqueue_index_and_count(rb_atomic_t combined, rb_atomic_t *enqueue_index, rb_atomic_t *count)
{
    if (enqueue_index) {
        *enqueue_index = (combined & PJOB_ASYNC_MASK_ENQUEUE_INDEX) >> PJOB_ASYNC_SHIFT_ENQUEUE_INDEX;
    }
    if (count) {
        *count = (combined& PJOB_ASYNC_MASK_COUNT) >> PJOB_ASYNC_SHIFT_COUNT;
    }
}

static inline rb_atomic_t
pjob_async_compose_enqueue_index_and_count(rb_atomic_t enqueue_index, rb_atomic_t count)
{
    return ((count << PJOB_ASYNC_SHIFT_COUNT) & PJOB_ASYNC_MASK_COUNT) |
            ((enqueue_index << PJOB_ASYNC_SHIFT_ENQUEUE_INDEX) & PJOB_ASYNC_MASK_ENQUEUE_INDEX);
}

static inline rb_atomic_t
pjob_async_count_subtract(rb_postponed_job_queues_t *pjq, rb_atomic_t sub)
{
    /* this load doesn't need to be atomic because we CAS it later */
    rb_atomic_t old_combined = pjq->async.enqueue_index_and_count;
    rb_atomic_t old_enqueue_index, old_count, new_count, new_combined, cas_result;
    while (true) {
        pjob_async_decompose_enqueue_index_and_count(old_combined, &old_enqueue_index, &old_count);
        new_count = old_count - sub;

        new_combined = pjob_async_compose_enqueue_index_and_count(old_enqueue_index, new_count);
        cas_result = RUBY_ATOMIC_CAS(pjq->async.enqueue_index_and_count, old_combined, new_combined);
        if (cas_result == old_combined) {
            break;
        }
        old_combined = cas_result;
    }

    pjob_async_decompose_enqueue_index_and_count(old_combined, NULL, &old_count);
    return old_count;

}

static inline bool
pjob_blocking_disable_gc(void)
{
    if (!ruby_thread_has_gvl_p()) {
        return false;
    }
    return !RB_TEST(rb_gc_disable_no_rest());
}

static inline void
pjob_blocking_reenable_gc(bool was_enabled)
{
    if (!was_enabled) {
        return;
    }
    rb_gc_enable();
}

void
rb_vm_postponed_job_atfork(void)
{
    rb_vm_t *vm = GET_VM();
    rb_postponed_job_queues_t *pjq = vm->postponed_job_queues;

    /* at fork, need to re-initialize the lock */
    rb_nativethread_lock_initialize(&pjq->blocking.lock);

    /* It's possible we have half-written jobs in the async buffer which will
     * never get written. We need to iterate the buffer and mark any non-ready
     * jobs as abandoned, so they will get skipped when we execute jobs. */
    rb_atomic_t index = pjq->async.dequeue_index;
    /* n.b. we _know_ there are no concurrent calls to flush, so original_job_count
     * might go up but can never come down during this call */
    rb_atomic_t original_combined = RUBY_ATOMIC_LOAD(pjq->async.enqueue_index_and_count);
    rb_atomic_t original_job_count;
    pjob_async_decompose_enqueue_index_and_count(original_combined, NULL, &original_job_count);
    rb_atomic_t jobs_processed = 0;
    while (original_job_count - jobs_processed > 0) {
        rb_pjob_async_t *job = &pjq->async.ringbuf[index];
        if (!(RUBY_ATOMIC_LOAD(job->flags) & PJOB_ASYNC_FLAG_READY)) {
            /* n.b. if there is a thread running right now in register_postponed_job,
             * this might wind up marking a job as abandoned that might actually
             * subsequently get the ready flag. The only way such a thread could exist
             * at the time the atfork handler is called is if it's created by an
             * extension doing something like pthread_atfork; this seems like
             * something that's not worth supporting. */
            RUBY_ATOMIC_OR(job->flags, PJOB_ASYNC_FLAG_ABANDONED);
        }
        jobs_processed++;
        pjob_async_increment_index_with_wrap(pjq, &index);
    }
    /* make sure we set the interrupt flag on _this_ thread if we carried any pjobs over
     * from the other side of the fork */
    if (original_job_count > 0) {
        RUBY_VM_SET_POSTPONED_JOB_INTERRUPT(get_valid_ec(vm));
    }
}

/* Frees the memory managed by the postponed job infrastructure at shutdown */
void
rb_vm_postponed_job_free(void)
{
    rb_vm_t *vm = GET_VM();
    rb_nativethread_lock_destroy(&vm->postponed_job_queues->blocking.lock);
    st_free_table(vm->postponed_job_queues->blocking.table);
    ruby_xfree(vm->postponed_job_queues);
    vm->postponed_job_queues = NULL;
}

/**
 * Atomically claims a slot in the ringbuffer and increments the count, in a single CAS instruction
 */
static inline bool
pjob_async_next_free_index(rb_postponed_job_queues_t *pjq, rb_atomic_t *i)
{
    /* this load does need to be atomic because we can decide to exit the function because of it
     * (because we might detect the ringbuf to be full) */
    rb_atomic_t old_combined = RUBY_ATOMIC_LOAD(pjq->async.enqueue_index_and_count);
    rb_atomic_t old_enqueue_index, old_count, new_enqueue_index, new_count, new_combined, cas_result;
    while (true) {
        pjob_async_decompose_enqueue_index_and_count(old_combined, &old_enqueue_index, &old_count);
        new_count = old_count + 1;
        new_enqueue_index = old_enqueue_index;
        pjob_async_increment_index_with_wrap(pjq, &new_enqueue_index);

        if (new_count > pjq->async.ringbuf_size) {
            /* we are full */
            return false;
        }

        new_combined = pjob_async_compose_enqueue_index_and_count(new_enqueue_index, new_count);
        cas_result = RUBY_ATOMIC_CAS(pjq->async.enqueue_index_and_count, old_combined, new_combined);
        if (cas_result == old_combined) {
            break;
        }
        old_combined = cas_result;
    }

    *i = old_enqueue_index;
    return true;
}

static int
postponed_job_register_async_impl(rb_postponed_job_func_t func, void *data, rb_atomic_t flags)
{
    rb_vm_t *vm = GET_VM();
    rb_postponed_job_queues_t *pjq = vm->postponed_job_queues;
    rb_execution_context_t *ec = get_valid_ec(vm);

    /* Find the next free index in the ringbuffer */
    rb_atomic_t index;
    if (!pjob_async_next_free_index(pjq, &index)) {
        /* ringbuffer was full */
        return 0;
    }

    /* write the job into the slot. Set the flags last, atomically, so that if a
     * CPU can read (flags | PJOB_READY) as true, it is guaranteed to see the
     * func/data arguments as well */
    rb_pjob_async_t *job = &pjq->async.ringbuf[index];
    /* annoyingly, this needs to be guaranteed to not tear because it could be read otherwise
     * unsynchronized in register_one to see if the func is already in the buffer */
    RUBY_ATOMIC_PTR_EXCHANGE(job->func, func);
    job->data = data;
    RUBY_ATOMIC_SET(job->flags, flags | PJOB_ASYNC_FLAG_READY);

    /* mark the EC for interruption*/
    RUBY_VM_SET_POSTPONED_JOB_INTERRUPT(ec);

    return 1;
}

 /*
  * return 0 if job buffer is full
  * Async-signal-safe
  */
int
rb_postponed_job_register(unsigned int flags, rb_postponed_job_func_t func, void *data)
{
    /* Historically, rb_postponed_job_register took a flags argument, but nothing
     * at all was ever done with it. This new implementation of postponed jobs
     * actually has a need for some flags its implementation, but this isn't
     * something which should be exposed to callers. So, the value of "flags" is
     * isgnored, and we pass some actual flags to _impl. */
    return postponed_job_register_async_impl(func, data, 0);
}

/*
 * return 0 if job buffer is full
 * Async-signal-safe
 */
int
rb_postponed_job_register_one(unsigned int flags, rb_postponed_job_func_t func, void *data)
{
    /* Make a BEST EFFORT attempt to only register one copy of this job.
     * We make the following guarantees with regards to calls to register_one:
     *  - If multiple calls to rb_postponed_job_register_one happen-before a call
     *    which checks vm_check_ints_blocking, we _do_ guarantee that it will only be
     *    executed once. That happens via a racy check here first, but
     *    rb_postponed_job_flush will actually enforce properly.
     *  - If a call to rb_postponed_job_register_one happens during a call to
     *    rb_postponed_job_flush, and there is already an instance of this job in the
     *    queue, it will be called once during the ongoing call to
     *    rb_postponed_job_flush, and possibly again during the _next_ call to
     *    rb_postponed_job_flush.
     */
    rb_postponed_job_queues_t *pjq = GET_VM()->postponed_job_queues;

    rb_atomic_t original_enqueue_index_and_count, original_job_count, index, jobs_scanned;
    original_enqueue_index_and_count = RUBY_ATOMIC_LOAD(pjq->async.enqueue_index_and_count);
    pjob_async_decompose_enqueue_index_and_count(original_enqueue_index_and_count, &index, &original_job_count);
    jobs_scanned = 0;
    while (original_job_count - jobs_scanned > 0) {
        pjob_async_decrement_index_with_wrap(pjq, &index);
        rb_pjob_async_t *job = &pjq->async.ringbuf[index];
        rb_atomic_t flags = RUBY_ATOMIC_LOAD(job->flags);
        if (flags & PJOB_ASYNC_FLAG_READY && !(flags & PJOB_ASYNC_FLAG_ABANDONED)) {
            /* we don't really need another memory fence here, but we _do_ need to make sure there's no tearing,
             * and the RUBY_ATOMIC_ header only has seq_cst atomics. It's not worth making a whole new family of
             * relaxed macros in atomic.h just for this */
            rb_postponed_job_func_t scanned_func = (rb_postponed_job_func_t)RUBY_ATOMIC_PTR_LOAD(job->func);
            if (scanned_func == func) {
                return 2;
            }
        }
        jobs_scanned++;
    }

    return postponed_job_register_async_impl(func, data, PJOB_ASYNC_FLAG_ONCE);
}

static int
workqueue_do_insert_under_lock(struct st_table *table, rb_postponed_job_func_t func, void *data, bool once)
{
    if (once) {
        if (st_lookup(table, (st_data_t)func, 0) != 0) {
            return 2;
        }
    }
    /* make sure the allocation in st_add_direct doesn't recursively trigger GC under the lock */
    bool was_gc_on = pjob_blocking_disable_gc();
    /* use st_add_direct to make st_table work like a queue. This approach was
     * originally committed by normalperson in 5a1dfb04, but had to be reverted as
     * it is not suitable for use from signal handlers. It is suitable for use in
     * blocking job registration, however. */
    st_add_direct(table, (st_data_t)func, (st_data_t)data);
    pjob_blocking_reenable_gc(was_gc_on);
    return 1;
}

int
rb_workqueue_register_impl(rb_postponed_job_func_t func, void *data, rb_atomic_t flags)
{
    rb_vm_t *vm = GET_VM();
    rb_postponed_job_queues_t *pjq = GET_VM()->postponed_job_queues;
    rb_execution_context_t *ec = get_valid_ec(vm);

    rb_nativethread_lock_lock(&pjq->blocking.lock);
    int ret = workqueue_do_insert_under_lock(pjq->blocking.table, func, data, flags);
    RUBY_VM_SET_POSTPONED_JOB_INTERRUPT(ec);
    rb_nativethread_lock_unlock(&pjq->blocking.lock);
    return ret;
}

/*
 * thread-safe and called from ruby or non-Ruby thread
 * returns true always.
 */

int
rb_workqueue_register(unsigned unused_flags, rb_postponed_job_func_t func, void *data)
{
    return rb_workqueue_register_impl(func, data, false);
}

/*
 * thread-safe and called from ruby or non-Ruby thread
 * returns true always.
 */
int
rb_workqueue_register_one(unsigned unused_flags, rb_postponed_job_func_t func, void *data)
{
    return rb_workqueue_register_impl(func, data, true);
}

void
rb_postponed_job_flush(rb_vm_t *vm)
{
    rb_postponed_job_queues_t *pjq = GET_VM()->postponed_job_queues;
    rb_execution_context_t *ec = GET_EC();
    const rb_atomic_t block_mask = POSTPONED_JOB_INTERRUPT_MASK | TRAP_INTERRUPT_MASK;
    volatile rb_atomic_t saved_mask = ec->interrupt_mask & block_mask;
    VALUE volatile saved_errno = ec->errinfo;

    /* Take the blocking queue out from pjq, and replace it, so that we can freely
    * iterate it & call the callbacks without having to hold the blocking lock */
    struct st_table *blocking_table;
    bool was_gc_on = pjob_blocking_disable_gc();
    rb_nativethread_lock_lock(&pjq->blocking.lock);
    blocking_table = pjq->blocking.table;
    pjq->blocking.table = st_init_numtable();
    rb_nativethread_lock_unlock(&pjq->blocking.lock);
    pjob_blocking_reenable_gc(was_gc_on);

    /* Drain the async job buffer into the blocking one */
    rb_atomic_t index = pjq->async.dequeue_index;
    rb_atomic_t original_enqueue_index_and_count = RUBY_ATOMIC_LOAD(pjq->async.enqueue_index_and_count);
    rb_atomic_t original_job_count;
    pjob_async_decompose_enqueue_index_and_count(original_enqueue_index_and_count, NULL, &original_job_count);
    rb_atomic_t jobs_drained = 0;
    while (original_job_count - jobs_drained > 0) {
        rb_pjob_async_t *job = &pjq->async.ringbuf[index];
        rb_atomic_t flags = RUBY_ATOMIC_EXCHANGE(job->flags, 0);
        /* If we have seen a job which is not marked as ready, that means some other
         * thread is in the process of writing the job data; we need to abort early
         * here because it is not guaranteed that job->func/job->data will be
         * meaningful */
        if (!(flags & PJOB_ASYNC_FLAG_READY)) {
            break;
        }
        if (!(flags & PJOB_ASYNC_FLAG_ABANDONED)) {
            /* copy the job at index into the blocking buffer */
            workqueue_do_insert_under_lock(blocking_table, job->func, job->data, flags & PJOB_ASYNC_FLAG_ONCE);
        }
        jobs_drained++;
        pjob_async_increment_index_with_wrap(pjq, &index);
    }
    /* non-atomic; dequeue_index is only read non-concurrently from this function. */
    pjq->async.dequeue_index = index;
    /* This subtraction will allow more jobs to be enqueued */
    rb_atomic_t previous_job_count = pjob_async_count_subtract(pjq, jobs_drained);
    if (previous_job_count - jobs_drained > 0) {
        /* Make sure we come back around if there are still jobs to be drained */
        RUBY_VM_SET_POSTPONED_JOB_INTERRUPT(ec);
    }

    /* We're now free to iterate & execute the jobs from the blocking table */
    ec->errinfo = Qnil;
    /* mask POSTPONED_JOB dispatch */
    ec->interrupt_mask |= block_mask;
    {
        EC_PUSH_TAG(ec);
        if (EC_EXEC_TAG() == TAG_NONE) {
            st_data_t k, v;
            while (st_shift(blocking_table, &k, &v)) {
                rb_postponed_job_func_t func = (rb_postponed_job_func_t)k;
                void *data = (void *)v;
                func(data);
            }
        }
        EC_POP_TAG();
    }
    /* restore POSTPONED_JOB mask */
    ec->interrupt_mask &= ~(saved_mask ^ block_mask);
    ec->errinfo = saved_errno;

    /* Historically, the thing which was done if a job threw an exception was to
     * keep the remaining jobs in the queue to execute next time. So, add any
     * remaining entries from our execution list back into the new blocking job
     * table */
    if (st_table_size(blocking_table) > 0) {
        rb_nativethread_lock_lock(&pjq->blocking.lock);
        st_data_t k, v;
        while (st_shift(blocking_table, &k, &v)) {
            rb_postponed_job_func_t func = (rb_postponed_job_func_t)k;
            void *data = (void *)v;
            workqueue_do_insert_under_lock(pjq->blocking.table, func, data, 0);
        }
        rb_nativethread_lock_unlock(&pjq->blocking.lock);
        RUBY_VM_SET_POSTPONED_JOB_INTERRUPT(ec);
    }
    st_free_table(blocking_table);
}
