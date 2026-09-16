#ifndef AURA_EMA_H
#define AURA_EMA_H

#include <stdint.h>

#define A_EMA_SHIFT 16
#define A_EMA_SCALE (1ULL << A_EMA_SCALE)

/* 0.1 x A_EMA_SCALE */
#define A_EMA_ALPHA 6554

static inline void aura_ema_init(uint64_t *ema_fp, uint64_t x) {
    *ema_fp = x << A_EMA_SHIFT;
}

static inline void a_ema_update(uint64_t *ema_fp, uint64_t x) {
    uint64_t x_fp = x << A_EMA_SHIFT;
    int64_t delta = (int64_t)x_fp - (int64_t)*ema_fp;
    *ema_fp += ((int64_t)A_EMA_ALPHA * delta) >> A_EMA_SHIFT;
}

static inline uint64_t aura_ema_get(uint64_t ema_fp) {
    return ema_fp >> A_EMA_SHIFT;
}

#endif
