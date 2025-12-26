#ifndef AURA_COMPILER_TOOLS_H
#define AURA_COMPILER_TOOLS_H

#define __user
#define __rcu
#define __read_mostly

#ifndef likely
#define likely(x) __builtin_expect(!!(x), 1)
#endif

#ifndef unlikely
#define unlikely(x) __builtin_expect(!!(x), 0)
#endif

#ifndef typeof
#define typeof __typeof__
#endif

#ifndef inline
#define inline __inline__
#endif

#ifndef same_type
#define same_type(a, b) __builtin_types_compatible_p(typeof(a), typeof(b))
#endif

#ifndef offsetof
#define offsetof(type, member) __builtin_offsetof(type, member)
#endif

#ifndef constant
#define constant(exp) __builtin_constant_p(exp)
#endif

#ifndef __unreachable
#define __unreachable() __builtin_unreachable()
#endif

#ifndef __always_inline
#define __always_inline __attribute__((always_inline))
#endif

#ifndef __aligned
#define __aligned(x) __attribute__((aligned(x)))
#endif

#ifndef __section
#define __section(sec_name) __attribute__((section(sec_name)))
#endif

#ifndef __used
#define __used __attribute_used__
#endif

#ifndef __noreturn
#define __noreturn __attribute__((noreturn))
#endif

#endif