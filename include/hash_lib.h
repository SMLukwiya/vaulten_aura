/*
 * fnv - Fowler/Noll/Vo- hash code
 *
 * To use the recommended 32 bit FNV-1 hash, pass FNV1_32_INIT as the
 * Fnv32_t hashval argument to fnv_32_buf() or fnv_32_str().
 *
 * To use the recommended 64 bit FNV-1 hash, pass FNV1_64_INIT as the
 * Fnv64_t hashval argument to fnv_64_buf() or fnv_64_str().
 *
 * To use the recommended 32 bit FNV-1a hash, pass FNV1_32A_INIT as the
 * Fnv32_t hashval argument to fnv_32a_buf() or fnv_32a_str().
 *
 * To use the recommended 64 bit FNV-1a hash, pass FNV1A_64_INIT as the
 * Fnv64_t hashval argument to fnv_64a_buf() or fnv_64a_str().
 *
 ***
 *
 * Please do not copyright this code.  This code is in the public domain.
 *
 * LANDON CURT NOLL DISCLAIMS ALL WARRANTIES WITH REGARD TO THIS SOFTWARE,
 * INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS. IN NO
 * EVENT SHALL LANDON CURT NOLL BE LIABLE FOR ANY SPECIAL, INDIRECT OR
 * CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM LOSS OF
 * USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR
 * OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR
 * PERFORMANCE OF THIS SOFTWARE.
 *
 * By:
 *	chongo <Landon Curt Noll> /\oo/\
 *      http://www.isthe.com/chongo/
 *
 * Share and Enjoy!	:-)
 */

#if !defined(__FNV_H__)
#define __FNV_H__

#include <sys/types.h>

#define FNV_VERSION "5.0.2" /* @(#) FNV Version */

typedef u_int32_t Fnv32_t;

/*
 * 32 bit FNV-1 and FNV-1a non-zero initial basis
 * NOTE: The FNV-1a initial basis is the same value as FNV-1 by definition.
 */
#define FNV1_32_INIT ((Fnv32_t)0x811c9dc5)
#define FNV1_32A_INIT FNV1_32_INIT

extern Fnv32_t fnv_32_buf(void *buf, size_t len, Fnv32_t hashval);
extern Fnv32_t fnv_32_str(char *buf, Fnv32_t hashval);

extern Fnv32_t fnv_32a_buf(void *buf, size_t len, Fnv32_t hashval);
extern Fnv32_t fnv_32a_str(char *buf, Fnv32_t hashval);

typedef u_int64_t Fnv64_t;

/*
 * 64 bit FNV-1 non-zero initial basis
 * NOTE: The FNV-1a initial basis is the same value as FNV-1 by definition.
 */
#define FNV1_64_INIT ((Fnv64_t)0xcbf29ce484222325ULL)
#define FNV1A_64_INIT FNV1_64_INIT

extern Fnv64_t fnv_64_buf(void *buf, size_t len, Fnv64_t hashval);
extern Fnv64_t fnv_64_str(char *buf, Fnv64_t hashval);

extern Fnv64_t fnv_64a_buf(void *buf, size_t len, Fnv64_t hashval);
extern Fnv64_t fnv_64a_str(char *buf, Fnv64_t hashval);

#endif /* __FNV_H__ */
