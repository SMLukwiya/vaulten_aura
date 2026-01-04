#ifndef AURA_DB_H
#define AURA_DB_H

#define _POSIX_C_SOURCE 200809L

#include "align_lib.h"
#include "encrypt_lib.h"
#include "error_lib.h"
#include "types_lib.h"

#include <stdint.h>

/* Inspired by APUE key-value db */

typedef void *AURA_DBHANDLE;

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

#define A_DB_FILE_MODE (S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH)

/* Namespaces */
typedef enum {
    A_DB_NS_FN = 1,   /* Function namespace */
    A_DB_NS_CFG = 2,  /* Config namespace*/
    A_DB_NS_STAT = 3, /* Stat namespace */
} aura_db_namespace;

/* Schemas */
typedef enum {
    A_DB_SCHEMA_FN_META_V1 = 1,
    A_DB_SCHEMA_CFG_KV_V1 = 2,
    A_DB_SCHEMA_STAT_DELTA = 3,
} aura_db_schema_id;

typedef enum {
    A_DB_REC_TOMBSTONE = 1
} aura_db_flags;

typedef enum {
    A_FNV1A_HASH_ALGO = 1,
} aura_db_hash_algo;

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
    char check_sum[DIGEST_LEN];
}; /* [key][data][padding] */

/* Bucket offset entry */
struct aura_db_bucket_entry {
    _Atomic off_t head_off; /* offset of newest record */
};

struct aura_db_wal_rec_hdr {
    u_int32_t magic;
    u_int16_t op;
    u_int16_t ns;
    uint16_t schema_id;
    u_int32_t key_len;
    u_int32_t data_len;
    struct aura_db_rec_len rec_len;
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

/** Create or open a database */
AURA_DBHANDLE aura_db_open(const char *, const char *, int, ...);

/**Store record with key and value into db */
int aura_db_put_record(AURA_DBHANDLE db, uint16_t namespace, uint16_t schema_id, struct aura_iovec *key, struct aura_iovec *data);

/** Close db plus associated buffer */
void aura_db_close(AURA_DBHANDLE);

/** Check if record with given key exists */
bool aura_db_record_exists(AURA_DBHANDLE db, uint16_t namespace, uint16_t scheme_id, struct aura_iovec *key);

/** Retrieve a record */
int aura_db_fetch_record(AURA_DBHANDLE db, uint16_t namespace, struct aura_iovec *key, struct aura_iovec *data_out);

/** Delete a record */
int aura_db_delete_record(AURA_DBHANDLE _db, uint16_t namespace, uint16_t schema_id, struct aura_iovec *key);

/* Dump record header */
void aura_db_dump_rec_header(struct aura_db_rec_hdr *hdr);

#endif /* AURA_DB_H */