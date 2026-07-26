#ifndef AURA_ENCRYPT_H
#define AURA_ENCRYPT_H

#include "types_lib.h"

#define A_DIGEST_LEN (256 / 8)

struct aura_iovec aura_decrypt_bytes(struct aura_iovec *bytes, const uint8_t *key_hex);

struct aura_iovec aura_encrypt_bytes(struct aura_iovec *bytes, const uint8_t *key);

int aura_calculate_digest(struct aura_iovec *bytes, struct aura_iovec *digest);

#endif