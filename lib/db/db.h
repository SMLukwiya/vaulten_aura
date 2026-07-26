#ifndef AURA_DB_H
#define AURA_DB_H

#define _POSIX_C_SOURCE 200809L

#include "align_lib.h"
#include "encrypt/lib.h"
#include "error_lib.h"
#include "sliding_buf.h"
#include "types_lib.h"
#include "utils_lib.h"

#include <stdint.h>
#include <sys/types.h>
#include <sys/uio.h> /* struct iovec */

/* Inspired by APUE key-value db */

typedef void *AURA_DBHANDLE;
typedef uint64_t lsn_t;
typedef uint64_t txid_t;
typedef uint8_t ns_t;
typedef uint8_t schema_id_t;

#define A_DB_HASH_BUCKET_CNT 1024
#define A_DB_HASH_BUCKET_MASK 1024 - 1

#define A_DB_TX_BUF_SZ (4 * 1024) /* 4KB */

#define A_DB_MAX_CONC_TX 64

#define A_DB_REC_NOT_FOUND 1
#define A_DB_JOB_ID_NONE 0
#define A_DB_NIL_TX_ID 0
#define A_DB_PREV_JOB_REC_NONE UINT64_MAX
#define A_DB_NIL_PREV_TX_REC_OFF UINT64_MAX
#define A_DB_NIL_FLAGS 0

#define A_DB_FILE_MODE (S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH)

#define A_DB_CORE_BASE 0  /* 0- 49 */
#define A_DB_FN_BASE 50   /* 50 - 99 */
#define A_DB_SRV_BASE 100 /* 100 - 149 */

#define A_DB_MAX_NAMESPACE 255
#define A_DB_MAX_SCHEMA_ID 255

/* Timeout infinity */
#define A_DB_TO_INFINITY 0

#define A_DB_MAX_FILE_PATH_LEN 128

typedef enum {
    A_DB_JOB_SCHEMA_ID = A_DB_CORE_BASE + 1,
    A_DB_JOB_STEP_SCHEMA_ID = A_DB_CORE_BASE + 2,
    A_DB_COMMIT_SCHEMA_ID = A_DB_CORE_BASE + 3,
    A_DB_CHECK_PNT_SCHEMA_ID = A_DB_CORE_BASE + 4
} aura_db_core_schema_id;

typedef enum {
    A_DB_JOB_NS = A_DB_CORE_BASE + 1,
    A_DB_TX_NS = A_DB_CORE_BASE + 2,
    A_DB_CHECK_PNT_NS = A_DB_CORE_BASE + 3
} aura_db_core_namespace;

typedef enum {
    A_DB_FLAG_NONE,
    A_DB_FLAG_REC_TOMBSTONE = 1
} aura_db_flag;

typedef enum {
    A_FNV1A_HASH_ALGO = 1,
} aura_db_hash_algo;

/** */
typedef enum {
    A_DB_EXEC_SYNC = 1,
    A_DB_EXEC_ASYNC
} aura_db_exec_mode;

typedef enum {
    A_DB_INSERT_OP = 1,
    A_DB_DELETE_OP,
    A_DB_COMPACT_OP,
    A_DB_JOB_EVENT_OP,
    A_DB_JOB_CREATE_OP,
    A_DB_JOB_STEP_OP,
    A_DB_JOB_FINISHED_OP,
    A_DB_JOB_CANCEL_OP
} aura_db_op;

typedef enum {
    A_DB_JOB_START,
    A_DB_JOB_RUNNING,
    A_DB_JOB_DONE,
    A_DB_JOB_FAILED
} aura_db_job_step;

typedef enum {
    A_DB_TX_FL_NIL = 0,
    A_DB_TX_FL_MR = 1,             /* Multi record transaction(opp of single record) */
    A_DB_TX_FL_SYNC = 1 << 1,      /* Record must make it to WAL before returning success */
    A_DB_TX_FL_ASYNC = 1 << 2,     /* Record only makes it to WAL buffer before returning success*/
    A_DB_TX_FL_VIRT = 1 << 3,      /* Virtual tx inside thread, contains virtual tx ID */
    A_DB_TX_FL_PRIV_DATA = 1 << 4, /* Transaction is keeping data in its private buffer */
} aura_db_tx_flag;

/* Fetched DB Record structure */
struct aura_db_rec {
    struct {
        char check_sum[A_DIGEST_LEN];
        uint64_t timestamp;
    } rec_meta;
    struct aura_iovec data;
};

/** @todo: remove */
// struct aura_db_completion {
//     uint64_t req_id;
//     int client_fd;
//     uint32_t state;
//     int status;
//     bool proceed;
//     void *user_data; /* opaque user data */
//     void (*on_complete)(struct aura_db_completion *, ssize_t db_res, AURA_DBHANDLE db);
// };

typedef enum {
    A_DB_STATE_STARTUP,
    A_DB_STATE_RECOVERY,
    A_DB_STATE_RUNNING,
    A_DB_STATE_QUIESCING,
    A_DB_STATE_STORAGE_SYNC,
    A_DB_STATE_THREAD_SHUTDOWN,
    A_DB_STATE_SHUTTING,
    A_DB_STATE_SHUTDOWN,
} aura_db_state_t;

typedef enum {
    A_DB_TX_NIL = 0,
    A_DB_TX_IN_PROGRESS,
    A_DB_TX_COMMITTED,
    A_DB_TX_ABORTED,
} aura_db_tx_state;

/* Database checkpoint flags */
typedef enum {
    A_DB_CHECKPOINT_TIMED = 1,
    A_DB_CHECKPOINT_LOG = 1 << 1,
    A_DB_CHECKPOINT_SHUTDOWN = 1 << 2,
    A_DB_CHECKPOINT_RECOVERY = 1 << 3,
    A_DB_CHECKPOINT_FORCE = 1 << 4,
} aura_db_checkpoint_t;

/* Write cache flags */
typedef enum {
    A_DB_WRITE_CACHE_SYNCING = 1,
    A_DB_WRITE_CACHE_DIRTY,
    A_DB_WRITE_CACHE_FLUSH_FORCE
} aura_db_write_buf_fl;

/* Log writer thread trigger flags */
typedef enum {
    A_DB_LOG_WRITER_TIMED,
    A_DB_LOG_WRITER_FORCE
} aura_db_log_writer_t;

/* Database shutdown modes */
typedef enum {
    A_DB_SHUTDOWN_GRACEFUL,
    A_DB_SHUTDOWN_FORCED,
    A_DB_SHUTDOWN_HALT
} aura_db_shutdown_mode;

/* Log record type */
typedef enum {
    A_DB_LOG_TYPE_NONE,
    A_DB_LOG_TYPE_UPDATE,
    A_DB_LOG_TYPE_BEGIN_CKPT,
    A_DB_LOG_TYPE_END_CKPT,
    A_DB_LOG_TYPE_COMMIT,
} aura_db_log_rec_type;

struct aura_db_checkpoint_begin {
    uint16_t format_version;
};

/* Global tx meta structure */
struct aura_db_tx_tab_ent {
    txid_t id;       /* Real transaction id */
    lsn_t last_lsn;  /* Latest LSN written by this transaction */
    pid_t thread_id; /* Thread that owns this slot */
    uint8_t state;   /* Transaction state */
    bool abort;      /* Set when caller is requested to abort */
};

/* Checkpoint structure */
struct aura_db_checkpoint {
    lsn_t rec_lsn;                                     /* Record position in file */
    lsn_t redo_lsn;                                    /* Redo start position in file */
    txid_t next_txid;                                  /* next available tx ID */
    struct timespec chkpt_time;                        /* Time checkpoint was taken */
    struct aura_db_tx_tab_ent trans[A_DB_MAX_CONC_TX]; /* Active transactions at checkpoint time */
    uint8_t format_version;                            /* checkpoint version */
};

/** Create or open a database */
AURA_DBHANDLE aura_db_open(struct aura_mem_ctx *mc, const char *db_path);

/* Close db release associated resources */
void aura_db_close(AURA_DBHANDLE _db);

/**Store record with key and value into db */
int aura_db_insert(AURA_DBHANDLE _db, ns_t namespace, schema_id_t schema_id,
                   uint16_t flags, aura_db_op op, struct aura_iovec *key,
                   struct aura_iovec *data);

/** Retrieve a record */
int aura_db_fetch(AURA_DBHANDLE _db, ns_t namespace, schema_id_t schema_id,
                  struct aura_iovec *key, struct aura_db_rec *data_out);

/** Delete a record */
int aura_db_delete(AURA_DBHANDLE _db, ns_t namespace, schema_id_t schema_id, struct aura_iovec *key);

/* Scan database file and print all records */
void aura_db_scan(AURA_DBHANDLE db);

/* Scan wal file and print all records */
void aura_db_wal_scan(AURA_DBHANDLE _db);

/**
 * Start a transaction
 */
int aura_db_transaction_begin(AURA_DBHANDLE _db, int tx_type, uint64_t timeout);

/**
 * Commit transaction
 */
int aura_db_transaction_commit(AURA_DBHANDLE _db);

/**
 * Cancel transaction
 */
int aura_db_transaction_cancel(AURA_DBHANDLE _db);

/* TEST HELPERS */
/* Open for testing */
AURA_DBHANDLE aura_db_test_open_with_log_writer(struct aura_mem_ctx *mc, const char *db_path, int oflag,
                                                uint32_t wrt_cache_sz, uint32_t read_cache_sz, ...);

/* Test close db */
void aura_db_test_close_with_bg_writer(AURA_DBHANDLE _db);
void aura_db_test_fields_with_bg_writer(AURA_DBHANDLE _db);

int aura_db_test_force_write_cache_flush(AURA_DBHANDLE _db);

int aura_db_test_fetch_from_write_cache(AURA_DBHANDLE _db, ns_t namespace, schema_id_t schema_id,
                                        struct aura_iovec *key, struct aura_db_rec *data_out);

int aura_db_test_fetch_db(AURA_DBHANDLE _db, ns_t namespace, schema_id_t schema_id,
                          struct aura_iovec *key, struct aura_db_rec *data_out);

void aura_db_test_write_cache_reset(AURA_DBHANDLE db);

#endif /* AURA_DB_H */