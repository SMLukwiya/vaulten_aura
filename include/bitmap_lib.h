#ifndef AURA_BITMAP_H
#define AURA_BITMAP_H

#include <stdbool.h>
#include <stdint.h>

#define A_BITS_PER_BYTE 8
#define A_BITS_PER_TYPE(type) (sizeof(type) * A_BITS_PER_BYTE)
#define A_DIV_ROUND_UP(a, b) (((a) + (b) - 1) / (b))

#define A_BITS_TO_LONG(bits) A_DIV_ROUND_UP((bits), A_BITS_PER_TYPE(long))
#define A_CREATE_BITMAP(bits, name) unsigned long name[A_BITS_TO_LONG(bits)]

#define A_BITS_PER_LONG A_BITS_PER_TYPE(long)
#define A_BIT_MASK(pos) (UL(1) << ((pos) % A_BITS_PER_LONG))
#define A_BIT_WORD(pos) ((pos) / A_BITS_PER_LONG)

#define A_GENMASK(h, l) (((~UL(0)) - (UL(1) << (l)) + 1) & (~UL(0) >> (A_BITS_PER_LONG - 1 - (h))))

/**
 * set a bit in memory
 * @pos: the bit to set
 * @addr: the starting address
 */
static inline void aura_set_bit(uint64_t pos, uint64_t *addr) {
    uint64_t mask = A_BIT_MASK(pos);
    uint64_t *adr = (uint64_t *)addr + A_BIT_WORD(pos);
    *adr |= mask;
}

/* clear bit in memory */
static inline void aura_clear_bit(uint64_t pos, uint64_t *addr) {
    uint64_t mask = A_BIT_MASK(pos);
    uint64_t *adr = (uint64_t *)addr + A_BIT_WORD(pos);
    *adr &= ~mask;
}

/**
 * Determine if a bit is set
 * @pos: bit number to test
 * @addr: Starting address
 */
static inline bool aura_test_bit(uint64_t pos, uint64_t *addr) {
    return 1UL & (addr[A_BIT_WORD(pos)] >> (pos & (A_BITS_PER_LONG - 1)));
}

/**
 * Clear bit and return its old value
 * @pos: Bit to clear
 * @addr: Starting address
 */
static inline bool aura_test_and_clear_bit(uint64_t pos, uint64_t *addr) {
    uint64_t mask = A_BIT_MASK(pos);
    uint64_t *adr = ((uint64_t *)addr + A_BIT_WORD(pos));
    uint64_t old = *adr;
    *adr &= ~mask;
    return (old & mask) != 0;
}

static inline uint32_t a_find_bit(uint64_t word) {
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
 * find the next set bit in memory
 * @addr: address to search
 * @offset: bit number to start search from
 * @size: bitmap size in bits
 * Return:
 * - bit number of the next set bit
 * - @size if not bit is set
 */
static inline uint64_t aura_find_next_bit(uint64_t *addr, uint64_t offset, uint64_t size) {
    uint64_t val;

    if (offset >= size)
        return size;

    /* check if any bit is set */
    val = *addr & A_GENMASK(size - 1, offset);
    return val ? a_find_bit(val) : size;
}

#endif