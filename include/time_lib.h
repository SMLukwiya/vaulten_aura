#ifndef AURA_TIME_H
#define AURA_TIME_H

#include <stdint.h>
#include <sys/time.h>
#include <time.h>

struct aura_time_window {
    time_t start;
    time_t end;
};

/* Get current time in nanoseconds */
static inline uint64_t aura_now_ns(void) {
    int res;
    struct timespec ts;
    res = clock_gettime(CLOCK_MONOTONIC, &ts);
    if (res != 0)
        return 0;
    return (uint64_t)(ts.tv_sec * 1000000000 + ts.tv_nsec);
}

/* Get current time in microseconds */
static inline uint64_t aura_now_ms(void) {
    int res;
    struct timespec ts;
    res = clock_gettime(CLOCK_MONOTONIC, &ts);
    if (res != 0)
        return 0;
    return (uint64_t)(ts.tv_sec * 1000 + ts.tv_nsec / 1000000);
}

/* Get current time time provided timespec */
static inline int aura_now_ts(struct timespec *ts) {
    return clock_gettime(CLOCK_MONOTONIC, ts);
}

#endif