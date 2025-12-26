#ifndef AURA_TRACING_H
#define AURA_TRACING_H

/* GCC */
void __cyg_profile_func_enter(void *this_fn, void *call_site);
void __cyg_profile_func_exit(void *this_fn, void *call_site);

#endif