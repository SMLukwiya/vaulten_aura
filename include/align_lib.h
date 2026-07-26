#ifndef AURA_ALIGN_H
#define AURA_ALIGN_H

#define _A_ALIGN(x, y) (((x) + ((typeof(x))(y) - 1)) & ~((typeof(x))(y) - 1))

/**
 * Align x up to y alignment
 */
#define A_ALIGN(x, y) _A_ALIGN((x), (y))

/**
 * Align x down to y alignment
 */
#define A_ALIGN_DOWN(x, y) _A_ALIGN((x) - ((y) - 1), (y))
#define A_IS_ALIGNED(x, y) (((x) & ((typeof(x))(a) - 1)) == 0)

#endif