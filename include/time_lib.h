#ifndef AURA_TIME_H
#define AURA_TIME_H

#include <stdint.h>
#include <sys/time.h>
#include <time.h>

#define a_time_ms_to_ns(ms) ((ms) * 1000000ULL)
#define a_time_s_to_ns(s) ((s) * 1000000000ULL)
#define a_time_s_to_ms(s) ((s) * 1000ULL)
#define a_time_ns_to_ms(ns) ((ns) * 1e-6)
#define a_time_ms_to_s(ms) ((ms) * 1e-3)

/* Returns true if time a is after time b */
#define a_time_after(a, b) ((long)((b) - (a)) < 0)

/* Returns true if time a is before time b */
#define a_time_before(a, b) a_time_after(b, a)

struct aura_time_window {
    time_t start;
    time_t end;
};

/* Get current time in nanoseconds */
static inline uint64_t aura_now_ns(int clock_id) {
    int res;
    struct timespec ts;
    res = clock_gettime(clock_id, &ts);
    if (res != 0)
        return 0;
    return (uint64_t)(a_time_s_to_ns(ts.tv_sec) + ts.tv_nsec);
}

/* Get current time in microseconds */
static inline uint64_t aura_now_ms(int clock_id) {
    int res;
    struct timespec ts;
    res = clock_gettime(clock_id, &ts);
    if (res != 0)
        return 0;
    return (uint64_t)(a_time_s_to_ms(ts.tv_sec) + a_time_ns_to_ms(ts.tv_nsec));
}

/* Get current time time provided timespec */
static inline int aura_now_ts(struct timespec *ts, int clock_id) {
    return clock_gettime(clock_id, ts);
}

#endif