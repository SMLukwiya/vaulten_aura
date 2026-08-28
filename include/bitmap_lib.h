#ifndef AURA_BITMAP_H
#define AURA_BITMAP_H

#include <stdbool.h>
#include <stdint.h>

#define A_BITS_PER_BYTE 8
#define A_BITS_PER_TYPE(type) (sizeof(type) * A_BITS_PER_BYTE)
#define A_DIV_ROUND_UP(a, b) (((a) + (b) - 1) / (b))

#define A_BITS_TO_LONG(bits) A_DIV_ROUND_UP((bits), A_BITS_PER_TYPE(long))
#define A_BITMAP_CREATE(bits, name) unsigned long name[A_BITS_TO_LONG(bits)]

#define A_BITS_PER_LONG A_BITS_PER_TYPE(long)
#define A_BIT_MASK(pos) (1UL << ((pos) % A_BITS_PER_LONG))
#define A_BIT_WORD(pos) ((pos) / A_BITS_PER_LONG)
/**
 * Generate a bitmap from
 * @l(low) position upto @(h) high position
 */
#define A_BITMAP_GENMASK(h, l) (((1UL << ((h) - (l) + 1)) - 1) << (l))

/**
 * set a bit in memory
 * @pos: the bit to set
 * @addr: the starting address
 */
static inline void aura_bitmap_set_bit(uint64_t pos, uint64_t *addr) {
    uint64_t mask = A_BIT_MASK(pos);
    uint64_t *adr = (uint64_t *)addr + A_BIT_WORD(pos);
    *adr |= mask;
}

/* clear bit in memory */
static inline void aura_bitmap_clear_bit(uint64_t pos, uint64_t *addr) {
    uint64_t mask = A_BIT_MASK(pos);
    uint64_t *adr = (uint64_t *)addr + A_BIT_WORD(pos);
    *adr &= ~mask;
}

/**
 * Determine if a bit is set
 * @pos: bit number to test
 * @addr: Starting address
 */
static inline bool aura_bitmap_test_bit(uint64_t pos, uint64_t *addr) {
    return 1UL & (addr[A_BIT_WORD(pos)] >> (pos & (A_BITS_PER_LONG - 1)));
}

/**
 * Clear bit and return its old value
 * @pos: Bit to clear
 * @addr: Starting address
 */
static inline bool aura_bitmap_test_and_clear_bit(uint64_t pos, uint64_t *addr) {
    uint64_t mask = A_BIT_MASK(pos);
    uint64_t *adr = ((uint64_t *)addr + A_BIT_WORD(pos));
    uint64_t old = *adr;
    *adr &= ~mask;
    return (old & mask) != 0;
}

static inline uint32_t a_bitmap_find_bit(uint64_t word) {
    uint32_t n = 0;

    if ((word & 0xffffffff) == 0) {
        n += 32;
        word >>= 32;
    }

    if ((word & 0xffff) == 0) {
        n += 16;
        word >>= 16;
    }

    if ((word & 0xff) == 0) {
        n += 8;
        word >>= 8;
    }

    if ((word & 0xf) == 0) {
        n += 4;
        word >>= 4;
    }

    if ((word & 0x3) == 0) {
        n += 2;
        word >>= 2;
    }

    if ((word & 0x1) == 0)
        n += 1;
    return n;
}

/**
 * Returns number of leading 0-bits in x.
 * NOTE: If x is 0, the result is undefined.
 */
static inline int a_clz32(unsigned int x) {
    return __builtin_clz(x);
}

/**
 * Returns the number of trailing 0-bits in x.
 * NOTE: If x is 0, the result is undefined.
 */
static inline int a_ctz32(unsigned int x) {
    return __builtin_ctz(x);
}

/**
 * Returns number of leading 0-bits in x.
 * NOTE: If x is 0, the result is undefined.
 */
static inline int a_clz64(unsigned long x) {
    return __builtin_clzll(x);
}

/**
 * Returns the number of trailing 0-bits in x.
 * NOTE: If x is 0, the result is undefined.
 */
static inline int a_ctz64(unsigned long x) {
    return __builtin_ctzll(x);
}

/**
 * find the next set bit in memory
 * @addr: address to search
 * @offset: bit number to start search from
 * @size: bitmap size in bits
 * Return:
 * - bit number of the next set bit
 * - @size if not bit is set
 */
static inline uint64_t aura_bitmap_find_next_bit(uint64_t *addr, uint64_t offset, uint64_t size) {
    uint64_t val;

    if (offset >= size)
        return size;

    /* check if any bit is set */
    val = *addr & A_BITMAP_GENMASK(size - 1, offset);
    return val ? a_ctz64(val) : size;
}

/* Find next empty bit in some defined array of bits */
static inline uint64_t aura_bitmap_find_next_empty_bit(uint64_t *addr, uint64_t offset, uint64_t size) {
    uint64_t val;

    if (offset >= size)
        return size;

    /* check if any bit is set */
    val = *addr & A_BITMAP_GENMASK(size - 1, offset);
    return ~val ? a_ctz64(~val) : size;
}

#endif