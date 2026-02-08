#ifndef AURA_DB_H
#define AURA_DB_H

#define _POSIX_C_SOURCE 200809L

#include "align_lib.h"
#include "encrypt_lib.h"
#include "error_lib.h"
#include "types_lib.h"
#include "utils_lib.h"

#include <stdint.h>
#include <sys/uio.h> /* struct iovec */

/* Inspired by APUE key-value db */

typedef void *AURA_DBHANDLE;

/* Limits */
#define A_DB_BUCKET_CNT 1024

/* Namespace prefixes */
#define A_DB_KEY_PREFIX_FUNC "fn"

/* Resource type suffixes */
#define A_DB_SCHEMA_SUFFIX_META "meta"
#define A_DB_SCHEMA_SUFFIX_CODE "code"
#define A_DB_SCHEMA_SUFFIX_CONFIG "config"
#define A_DB_SCHEMA_SUFFIX_STAT "stat"
#define A_DB_SCHEMA_SUFFIX_STATE "state"

#define A_DB_REC_NOT_FOUND 1

#define A_DB_JOB_ID_NONE 0
#define A_DB_PREV_JOB_REC_NONE 0

#define A_DB_FILE_MODE (S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH)

/* Namespaces */
typedef enum {
    A_DB_NS_FN = 1, /* Function namespace */
    // A_DB_NS_STAT,      /* Stat namespace */
    A_DB_NS_JOB,       /* Job namespace */
    A_DB_NS_CHECK_PNT, /* Check point namespace */
} aura_db_namespace;

/* Schemas */
typedef enum {
    A_DB_SCHEMA_FN_CODE_V1 = 1,
    A_DB_SCHEMA_FN_META_V1,
    A_DB_SCHEMA_FN_CONFIG_V1,
    A_DB_SCHEMA_FN_STAT_DELTA,
    A_DB_SCHEMA_JOB_V1,
    A_DB_SCHEMA_JOB_STEP_V1,
    A_DB_SCHEMA_FN_PETITE_V1,
    A_DB_SCHEMA_FN_STATE_V1,
    A_DB_SCHEMA_CHECK_PNT,
    A_DB_SCHEMA_FNS,
} aura_db_schema_id;

typedef enum {
    A_DB_FLAG_NONE,
    A_DB_FLAG_REC_TOMBSTONE = 1
} aura_db_flag;

typedef enum {
    A_FNV1A_HASH_ALGO = 1,
} aura_db_hash_algo;

/** */
typedef enum {
    A_DB_EXEC_DIRECT = 1,
    A_DB_EXEC_ASYNC
} aura_db_exec_mode;

typedef enum {
    A_DB_OP_INSERT = 1,
    A_DB_OP_DELETE,
    A_DB_OP_COMPACT,
    A_DB_JOB_OP_EVENT,
    A_DB_JOB_OP_CREATE,
    A_DB_JOB_OP_STEP,
    A_DB_JOB_OP_FINAL,
    A_DB_JOB_OP_CANCEL
} aura_db_op;

typedef enum {
    A_DB_JOB_START,
    A_DB_JOB_RUNNING,
    A_DB_JOB_DONE,
    A_DB_JOB_FAILED
} aura_db_job_step;

/* Fetched DB Record structure */
struct aura_db_rec {
    struct {
        char check_sum[DIGEST_LEN];
        uint64_t timestamp;
    } rec_meta;
    // struct aura_iovec key;
    struct aura_iovec data;
};

struct aura_db_completion {
    uint64_t req_id;
    int client_fd;
    uint32_t state;
    int status;
    bool proceed;
    void *user_data; /* opaque user data */
    void (*on_complete)(struct aura_db_completion *, ssize_t db_res);
};

/* DB write request structure */
struct aura_db_write_req {
    aura_db_op op;
    aura_db_namespace namespace;
    aura_db_schema_id schema_id;
    struct aura_iovec *key;
    struct aura_iovec *data;
    uint16_t flags;
    /* Job related */
    uint64_t job_id;
    uint64_t prev_job_rec; /* Job record that appears before this in the chain */
    uint16_t job_type;
    struct aura_list_head w_list;
    struct aura_db_completion *completion;
};

/* DB job record structure */
struct aura_db_job_rec {
    uint32_t magic;
    uint32_t version;
    uint64_t job_id;
    uint16_t job_type;
    uint8_t state;         /* Job state: start, running or done */
    uint64_t last_rec_off; /* Last record written for this job */
    uint64_t created_at;
    int32_t error_code;
    uint64_t ttl_epoch; /* GC */
};

/* DB job step structure */
struct aura_db_job_step_rec {
    uint32_t magic;
    uint32_t version;
    uint64_t job_id;
    uint16_t job_type;
    uint8_t step;     /* Local state that depends on record kind */
    uint8_t progress; /* Percentage progress */
    int error;
    uint64_t updated_at;
};

/** Create or open a database */
AURA_DBHANDLE aura_db_open(struct aura_memory_ctx *mc, const char *app_path, const char *db_pathname, int oflag, ...);

/**Store record with key and value into db */
ssize_t aura_db_record_insert(AURA_DBHANDLE _db, uint16_t namespace, uint16_t schema_id, uint64_t job_id, uint64_t prev_job_rec, aura_db_op op,
                              struct aura_iovec *key, struct aura_iovec *data, aura_db_exec_mode exec_mode, struct aura_db_completion *completion);

/** Close db release associated resources */
void aura_db_close(AURA_DBHANDLE);

/** Retrieve a record */
int aura_db_record_fetch(AURA_DBHANDLE db, uint16_t namespace, uint16_t schema_id, struct aura_iovec *key, struct aura_db_rec *data_out);

/** Delete a record */
int aura_db_record_delete(AURA_DBHANDLE _db, uint16_t namespace, uint16_t schema_id, uint64_t job_id,
                          struct aura_iovec *key, aura_db_exec_mode exec_mode, struct aura_db_completion *comp);

/* Get database true size */
size_t aura_db_get_size(AURA_DBHANDLE db);

/* Get database record count */
uint64_t aura_db_get_record_cnt(AURA_DBHANDLE _db);

/* Scan database file and print all records */
void aura_db_scan(AURA_DBHANDLE db);

/* Scan wal file and print all records */
void aura_db_wal_scan(AURA_DBHANDLE _db);

/* Launch database background tasks */
int aura_db_start_bg_tasks(AURA_DBHANDLE db);

/** Run the provided function on each record upto record_cnt */
int aura_db_record_for_each(AURA_DBHANDLE _db, uint64_t record_cnt, uint16_t namespace,
                            uint16_t schema_id, int (*fn)(struct iovec));

/**/
uint64_t aura_db_job_insert(AURA_DBHANDLE _db, uint32_t job_type, uint8_t state, uint64_t timeout, int error,
                            aura_db_exec_mode exec_mode, struct aura_db_completion *completion);

/**/
struct aura_db_job_rec *aura_db_job_fetch(AURA_DBHANDLE _db, uint64_t job_id, int *error);

/**/
int aura_db_job_step_insert(AURA_DBHANDLE _db, uint64_t job_id, uint32_t job_type, uint8_t step,
                            struct aura_iovec *target, aura_db_exec_mode exec_mode, struct aura_db_completion *comp);

/**/
int aura_db_job_update(AURA_DBHANDLE _db, uint64_t job_id, uint16_t state, int error, uint64_t rec_off,
                       aura_db_exec_mode exec_mode, struct aura_db_completion *comp);

/**/
struct aura_db_job_step_rec *aura_db_job_step_fetch(AURA_DBHANDLE _db, uint16_t job_type, struct aura_iovec *target);
#endif /* AURA_DB_H */