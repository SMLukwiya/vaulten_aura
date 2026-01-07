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

/* Get database true size */
size_t aura_db_get_size(AURA_DBHANDLE db);

/* Scan database file and print all records */
void aura_db_scan(AURA_DBHANDLE db);

/* Scan wal file and print all records */
void aura_db_wal_scan(AURA_DBHANDLE _db);

#endif /* AURA_DB_H */