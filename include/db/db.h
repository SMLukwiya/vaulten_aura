#ifndef AURA_DB_H
#define AURA_DB_H

#define _POSIX_C_SOURCE 200809L

#include "align_lib.h"
#include "error_lib.h"

/* Inspired by APUE key-value db */

typedef void *AURA_DBHANDLE;

AURA_DBHANDLE aura_db_open(const char *, int, ...);
void aura_db_close(AURA_DBHANDLE);
int aura_db_put_record(AURA_DB *db, uint16_t namespace, uint16_t schema_id, struct aura_iovec *key, struct aura_iovec *data);
void db_rewind(AURA_DBHANDLE);

/* Limits */
#define A_DB_BUCKET_CNT 1024

/* Namespace prefixes */
#define A_DB_NS_PREFIX_FUNC "func"
#define A_DB_NS_PREFIX_CONFIG "config"
#define A_DB_NS_PREFIX_STAT "stats"

/* Resource type suffixes */
#define A_DB_SUFFIX_META "meta"
#define A_DB_SUFFIX_CODE "code"

#define A_DB_REC_NOT_FOUND 1

/* Namespaces */
typedef enum {
    A_NS_FN = 1,   /* Function namespace */
    A_NS_CFG = 2,  /* Config namespace*/
    A_NS_STAT = 3, /* Stat namespace */
} aura_db_namespace;

/* Schemas */
typedef enum {
    A_SCHEMA_FN_META_V1 = 1,
    A_SCHEMA_CFG_KV_V1 = 2,
    A_SCHEMA_STAT_DELTA = 3,
} aura_db_schema_id;

typedef enum {
    A_DB_REC_TOMBSTONE = 1
} aura_db_flags;

struct aura_fn_stat_delta {
    u_int64_t ts;
    int64_t delta;
};

/* Record len structure */
struct aura_db_rec_len {
    size_t raw_len;     /* Exact record length not aligned */
    size_t aligned_len; /* Record len aligned */
};

/* Internal */
struct aura_db_rec_hdr {
    u_int32_t magic;
    u_int32_t version;
    u_int16_t ns; /* namespace */
    u_int16_t schema_id;
    u_int16_t flags;
    struct aura_db_rec_len rec_len;
    u_int32_t key_len;
    u_int32_t data_len;
    u_int64_t timestamp;
    u_int64_t prev_off; /* bucket chain */
}; /* [key][data][padding] */

struct aura_db_bucket_entry {
    _Atomic u_int64_t head_off; /* offset of newest record */
};

struct aura_db_wal_rec {
    u_int32_t magic;
    u_int16_t op;
    u_int16_t ns;
    u_int32_t key_len;
    u_int32_t data_len;
    u_int64_t timestamp;
}; /* [key][data] */

/**
 * Get record size possibly 8-byte aligned
 */
static inline struct aura_db_rec_len a_get_db_record_len(size_t key_len, size_t data_len) {
    struct aura_db_rec_len len;

    len.raw_len = sizeof(struct aura_db_rec_hdr) + key_len + data_len;
    len.aligned_len = A_ALIGN(len.raw_len, sizeof(void *));
    return len;
}

#endif /* AURA_DB_H */