#include "encrypt_lib.h"
#include "error_lib.h"
#include "utils_lib.h"

#include "types_lib.h"
#include <openssl/core_names.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/ssl.h>
#include <stdbool.h>
#include <sys/uio.h>

#define BLOCK_SIZE 16 /* 256 bits AES */
#define KEY_LEN 32
#define INIT_VEC_LEN 12
#define AUTH_TAG_LEN 16

static inline bool aura_generate_key(uint8_t *buf, size_t len) {
    int res;

    if (!buf)
        return false;

    res = RAND_bytes(buf, len);
    if (res != 0) {
        return false;
    }
    return true;
}

struct aura_iovec aura_encrypt_bytes(struct aura_iovec *bytes, const uint8_t *key) {
    bool res;
    int ok, out_nbytes;
    size_t in_nbytes, total_written, total_read;
    EVP_CIPHER_CTX *ctx = NULL;
    uint8_t *out_buf, *dest_start;
    uint8_t init_vec[INIT_VEC_LEN];
    uint8_t auth_tag[AUTH_TAG_LEN];
    struct aura_iovec enc;

    enc.base = NULL;
    enc.len = 0;
    out_buf = malloc(bytes->len + BLOCK_SIZE + INIT_VEC_LEN + AUTH_TAG_LEN);
    if (!out_buf)
        return enc;

    /* generate initialization vector */
    res = aura_generate_key(init_vec, INIT_VEC_LEN);
    if (res == false)
        goto err_outbuf;

    ctx = EVP_CIPHER_CTX_new();
    if (!ctx)
        goto err_outbuf;

    ok = EVP_EncryptInit(ctx, EVP_aes_256_gcm(), key, init_vec);
    if (ok != 0)
        goto err_cipher_ctx;

    total_written = 0;
    total_read = 0;
    dest_start = out_buf;
    while (total_read < bytes->len) {
        out_nbytes = 0;
        /* read in 4k chunks, get the minimum between 4k and what is left */
        in_nbytes = a_min(bytes->len - total_read, 4096);
        ok = EVP_EncryptUpdate(ctx, out_buf, &out_nbytes, bytes->base + total_read, in_nbytes);
        if (ok == 0)
            goto err_cipher_ctx;
        out_buf += out_nbytes;
        total_written += out_nbytes;
        total_read += in_nbytes;
    }

    out_nbytes = 0;
    ok = EVP_EncryptFinal(ctx, out_buf, &out_nbytes);
    if (ok == 0)
        goto err_cipher_ctx;
    out_buf += out_nbytes;
    total_written += out_nbytes;

    /* finalize to get authentication tag */
    ok = EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, AUTH_TAG_LEN, auth_tag);
    if (ok == 0)
        goto err_cipher_ctx;

    /* Append initialization vector */
    snprintf(out_buf, INIT_VEC_LEN, "%s", init_vec);
    out_buf += INIT_VEC_LEN;
    total_written += INIT_VEC_LEN;

    /* Append authentication tag */
    snprintf(out_buf, AUTH_TAG_LEN, "%s", auth_tag);
    total_written += AUTH_TAG_LEN;

    enc.base = dest_start;
    enc.len = total_written;

    EVP_CIPHER_CTX_free(ctx);
    return enc;

err_cipher_ctx:
    EVP_CIPHER_CTX_free(ctx);
err_outbuf:
    free(out_buf);
    return enc;
}

struct aura_iovec aura_decrypt_bytes(struct aura_iovec *bytes, const uint8_t *key_hex) {
    size_t decode_length, key_len;
    int out_nbytes;
    size_t in_nbytes, total_read, total_written;
    uint8_t *key;
    uint8_t init_vec[INIT_VEC_LEN];
    uint8_t auth_tag[AUTH_TAG_LEN];
    uint8_t *out_buf, *dest_start;
    EVP_CIPHER_CTX *ctx;
    struct aura_iovec dec;
    int ok;

    dec.base = NULL;
    dec.len = 0;

    if (bytes->len < (INIT_VEC_LEN + KEY_LEN)) {
        return dec;
    }

    out_buf = malloc(bytes->len);
    if (!out_buf)
        return dec;

    key = OPENSSL_hexstr2buf(key_hex, &key_len);
    if (!key || key_len != KEY_LEN) {
        goto err_outbuf;
    }

    ctx = EVP_CIPHER_CTX_new();
    if (!ctx)
        goto err_key;

    decode_length = bytes->len - (INIT_VEC_LEN + AUTH_TAG_LEN);
    /* read initialization vector */
    snprintf(init_vec, sizeof(init_vec), "%s", bytes->base + decode_length);
    ok = EVP_DecryptInit(ctx, EVP_aes_256_gcm(), key, init_vec);
    if (ok == 0) {
        goto err_cipher_ctx;
    }

    dest_start = out_buf;
    total_read = 0;
    total_written = 0;
    while (total_read < decode_length) {
        in_nbytes = a_min(bytes->len - total_read, 4096);
        out_nbytes = 0;
        ok = EVP_DecryptUpdate(ctx, out_buf, &out_nbytes, bytes->base + total_read, in_nbytes);
        if (ok == 0)
            goto err_cipher_ctx;
        out_buf += out_nbytes;
        total_written += out_nbytes;
        total_read += in_nbytes;
    }

    /* read authentication tag */
    snprintf(auth_tag, sizeof(auth_tag), "%s", bytes->base + decode_length + INIT_VEC_LEN);
    ok = EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, AUTH_TAG_LEN, auth_tag);
    if (ok == 0)
        goto err_cipher_ctx;

    /* finalize decryption */
    out_nbytes = 0;
    ok = EVP_DecryptFinal(ctx, out_buf, &out_nbytes);
    if (ok == 0)
        goto err_cipher_ctx;
    total_written += out_nbytes;

    dec.base = dest_start;
    dec.len = total_written;

    EVP_CIPHER_CTX_free(ctx);
    return dec;

err_cipher_ctx:
    EVP_CIPHER_CTX_free(ctx);
err_key:
    if (key)
        OPENSSL_free(key);
err_outbuf:
    free(out_buf);
    return dec;
}

/* calculate file digest and store in digest buffer */
struct aura_iovec aura_calculate_digest(struct aura_iovec *bytes) {
    EVP_MD_CTX *digest_context;
    size_t in_nbytes, total_read;
    struct aura_iovec md;
    int ok;

    md.base = NULL;
    md.len = 0;
    md.base = malloc(DIGEST_LEN);
    if (!md.base)
        return md;

    if (bytes->base == NULL || bytes->len == 0)
        return md;

    digest_context = EVP_MD_CTX_new();
    if (!digest_context)
        goto err_md;

    ok = EVP_DigestInit(digest_context, EVP_blake2s256());
    if (ok == 0) {
        goto err_digest_ctx;
    }

    total_read = 0;
    while (total_read < bytes->len) {
        in_nbytes = a_min(bytes->len - total_read, 4096);
        ok = EVP_DigestUpdate(digest_context, bytes->base + total_read, in_nbytes);
        if (ok == 0) {
            return md;
        }
        total_read += in_nbytes;
    }

    ok = EVP_DigestFinal(digest_context, md.base, NULL);
    if (ok == 0) {
        goto err_digest_ctx;
    }

    md.len = DIGEST_LEN;
    EVP_MD_CTX_free(digest_context);
    return md;

err_digest_ctx:
    EVP_MD_CTX_free(digest_context);
err_md:
    free(md.base);
    return md;
}
