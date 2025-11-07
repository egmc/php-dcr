#ifndef __USDT_BPF_H
#define __USDT_BPF_H

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

/*
 * BPF_USDT is a macro for USDT (User Statically-Defined Tracing) probes.
 * It helps extract arguments from USDT probes in a portable way.
 */

#if defined(bpf_target_x86)

/* x86-64 specific USDT argument handling */
#define BPF_USDT(name, args...) \
    name(struct pt_regs *ctx); \
    static __always_inline typeof(name(0)) \
    ____##name(struct pt_regs *ctx, ##args); \
    typeof(name(0)) name(struct pt_regs *ctx) \
    { \
        _Pragma("GCC diagnostic push") \
        _Pragma("GCC diagnostic ignored \"-Wint-conversion\"") \
        return ____##name(ctx, (void *)PT_REGS_PARM1(ctx), \
                              (void *)PT_REGS_PARM2(ctx), \
                              (void *)PT_REGS_PARM3(ctx), \
                              (void *)PT_REGS_PARM4(ctx), \
                              (void *)PT_REGS_PARM5(ctx), \
                              (void *)PT_REGS_PARM6(ctx)); \
        _Pragma("GCC diagnostic pop") \
    } \
    static __always_inline typeof(name(0)) \
    ____##name(struct pt_regs *ctx, ##args)

#elif defined(bpf_target_arm64)

/* ARM64 specific USDT argument handling */
#define BPF_USDT(name, args...) \
    name(struct pt_regs *ctx); \
    static __always_inline typeof(name(0)) \
    ____##name(struct pt_regs *ctx, ##args); \
    typeof(name(0)) name(struct pt_regs *ctx) \
    { \
        _Pragma("GCC diagnostic push") \
        _Pragma("GCC diagnostic ignored \"-Wint-conversion\"") \
        return ____##name(ctx, (void *)PT_REGS_PARM1(ctx), \
                              (void *)PT_REGS_PARM2(ctx), \
                              (void *)PT_REGS_PARM3(ctx), \
                              (void *)PT_REGS_PARM4(ctx), \
                              (void *)PT_REGS_PARM5(ctx), \
                              (void *)PT_REGS_PARM6(ctx), \
                              (void *)PT_REGS_PARM7(ctx), \
                              (void *)PT_REGS_PARM8(ctx)); \
        _Pragma("GCC diagnostic pop") \
    } \
    static __always_inline typeof(name(0)) \
    ____##name(struct pt_regs *ctx, ##args)

#else

/* Generic fallback */
#define BPF_USDT(name, args...) \
    name(struct pt_regs *ctx); \
    static __always_inline typeof(name(0)) \
    ____##name(struct pt_regs *ctx, ##args); \
    typeof(name(0)) name(struct pt_regs *ctx) \
    { \
        _Pragma("GCC diagnostic push") \
        _Pragma("GCC diagnostic ignored \"-Wint-conversion\"") \
        return ____##name(ctx, (void *)PT_REGS_PARM1(ctx), \
                              (void *)PT_REGS_PARM2(ctx), \
                              (void *)PT_REGS_PARM3(ctx), \
                              (void *)PT_REGS_PARM4(ctx), \
                              (void *)PT_REGS_PARM5(ctx), \
                              (void *)PT_REGS_PARM6(ctx)); \
        _Pragma("GCC diagnostic pop") \
    } \
    static __always_inline typeof(name(0)) \
    ____##name(struct pt_regs *ctx, ##args)

#endif

#endif /* __USDT_BPF_H */
