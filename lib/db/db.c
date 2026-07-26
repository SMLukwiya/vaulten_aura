#include "db.h"
#include "bitmap_lib.h"
#include "bug_lib.h"
#include "file/lib.h"
#include "hasher_lib.h"
#include "list_lib.h"
#include "mem.h"
#include "slab.h"
#include "stdatomic.h"
#include "string_lib.h"
#include "time_lib.h"

#include <dirent.h>
#include <errno.h>
#include <fcntl.h> /* open & db_open flags */
#include <pthread.h>
#include <semaphore.h>
#include <stdarg.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

#define A_DB_MAX_TX_REC_CNT 64         /* Max nr of records per transaction */
#define A_WAL_BUF_SZ (8 * 1024 * 1024) /* 8MB */
#define A_DB_TH_CNT 16                 /* DB thread count */
#define A_DB_NR_THREADS 3              /* Nr of DB threads */

#define A_DB_TX_PRIVATE_DATA_SZ (64 * 1024) /* 64KB */

/**
 * Wal writer thread sleeps for
 * 5ms intervals before attempting to
 * flush again
 */
#define A_DB_WAL_WRITER_INTERVAL a_time_ms_to_s(500)
#define A_DB_CHECKPOINTER_INTERVAL a_time_ms_to_s(1000)
#define A_DB_BG_WRITER_INTERVAL a_time_ms_to_s(1000)

#define A_DB_READ_CACHE_BUF_SZ (4 * 1024 * 1024)                             /* 4MB */
#define A_DB_WRITE_CACHE_BUF_SZ (4 * 1024 * 1024)                            /* 4MB */
#define A_DB_WRITE_CACHE_LOW_BUF_THRESHOLD(size) ((size >> 1) + (size >> 2)) /* 0.75 cache size */

#define A_DB_LOG_SZ_THRESHOLD (1 * 1024 * 1024) /* 1MB */

#define A_DB_GRACEFUL_SHUTDOWN_TIMEOUT 30 /* 30 seconds */

/* Time given to active tx to complete when taking checkpoint */
#define A_DB_TX_CHECKPOINT_WAIT 1000 /* 1000ms */

#define A_DB_MAGIC 0x5D5D5D5D
#define A_DB_REC_MAGIC 0xED5EC001
#define A_DB_WAL_MAGIC 0xED3A1001
#define A_DB_CACHE_SIZE (1024 * 1024) /* 1MB */
#define A_DB_CHECKPOINT_KEY "checkpoint"

static pthread_barrier_t barrier;

/**
 * Last important lsn appended to WAL
 * Updated by any thread flushing the log buffer
 */
static _Atomic lsn_t last_important_lsn;
/**
 * Last checkpoint lsn
 * Updated by checkpointer thread
 */
static _Atomic lsn_t last_checkpoint_lsn;

/**
 * global flushed lsn represents the start of the
 * next record to be flushed. Synchronous operations
 * use this to ensure data is durable before returning
 * an ack to the user. This value can safely start
 * at 0 since the first flush operation will set it to
 * the correct value anyway.
 */
static uint64_t glob_flushed_lsn = 0;

/* Bucket offset entry */
struct aura_db_bucket_entry {
    _Atomic lsn_t head_off; /* offset of newest record */
};

/* Record len structure */
struct aura_db_rec_len {
    uint64_t raw_len;     /* Exact record length */
    uint64_t aligned_len; /* Aligned record len */
};

/**
 * Record header structure
 */
struct aura_db_rec_hdr {
    uint32_t magic;                 /* Unique record header identifier */
    txid_t tx_id;                   /* Transaction id */
    lsn_t rec_off;                  /* Records position in db file */
    lsn_t prev_off;                 /* position of prev record as chained in the hash bucket */
    uint64_t prev_cache_off;        /* position of prev record in cache buffer */
    lsn_t prev_tx_rec_off;          /* position of prev record that is part of the same transaction */
    struct aura_db_rec_len rec_len; /* Record length */
    uint64_t timestamp_ms;          /* Time record was created */
    uint32_t hash;                  /* Records hash */
    uint32_t key_len;               /* Records key length */
    uint32_t data_len;              /* Records Data length */
    ns_t ns;                        /* Records namespace identifier */
    schema_id_t schema_id;          /* Records schema identifier */
    uint8_t flags;                  /* Record flags */
    char checksum[A_DIGEST_LEN];    /* Records checksum */
}; /* [key][data][padding] */

/* WAL record header structure */
struct aura_db_wal_rec_hdr {
    txid_t tx_id;     /* Transaction ID */
    lsn_t lsn;        /* Position of record in WAL */
    lsn_t prev_lsn;   /* Previous record position with same tx id */
    uint64_t rec_len; /* Record length */
    uint32_t magic;   /* Unique wal header identifier */
    uint8_t op;       /* Database operation */
    uint8_t type;     /* WAL record type */
}; /* [record] */

typedef enum {
    A_DB_THREAD_INVALID = 0,
    A_DB_THREAD_WAL_WRITER,
    A_DB_THREAD_BG_WRITER,
    A_DB_THREAD_CHECKPOINTER,
    A_DB_THREAD_COMPACTOR
} aura_db_bg_worker_t;

typedef enum {
    A_DB_THREAD_BG_WRITER_SHUTDOWN = 1,
    A_DB_THREAD_WAL_WRITER_SHUTDOWN
} aura_db_bg_worker_flag;

/* Thread status */
typedef enum {
    A_DB_BG_TH_INVALID,
    A_DB_BG_TH_RUNNING,
    A_DB_BG_TH_STOPPED,
    A_DB_BG_TH_SHUTTING_DOWN,
} aura_db_th_status;

/* DB Record data structure */
struct aura_db_rdata {
    // struct aura_list_head list;
    const void *data; /* Pointer to record data chunk */
    uint32_t len;     /* Length of record data chunk */
};

/* Tx structure */
struct aura_db_tx {
    txid_t id;                                       /* Transaction id */
    uint64_t timestamp;                              /* Tx start time */
    uint64_t ttl;                                    /* Tx timeout */
    struct aura_db_rdata rdata[A_DB_MAX_TX_REC_CNT]; /* Stage chunks of record data for processing */
    struct aura_sliding_buf priv_buf;                /* Tx private buffer */
    uint32_t rdata_cnt;                              /* WAL record fragment count */
    uint32_t rec_cnt;                                /* WAL record cnt for transaction */
    uint32_t rec_len;                                /* Total WAL record len */
    uint32_t max_priv_data_sz;                       /* Max private data allowed per tx */
    uint32_t reserved_off;                           /* reserved start offset in WAL buffer */
    uint8_t kind;                                    /* Kind of transaction */
    uint8_t state;                                   /* Transaction state */
    uint8_t op;                                      /* Database Operation */
    uint8_t flags;
};

/* DB db structure */
struct aura_db_th {
    pthread_t handle;
    aura_db_bg_worker_t wrk_type; /* Worker type */
    void *(*fn)(void *);          /* Main thread function */
    void (*shutdown_fn)(void *);  /* Called to tell thread to shutdown */
    uint32_t pool_idx;
    uint8_t status;
};

struct aura_db_data {
    int fd;
    pthread_mutex_t lock; /* Protect structure */
};

/* DB WAL structure */
struct aura_db_wal {
    int fd;                          /* WAL file fd */
    lsn_t write_lsn;                 /* current write offset in WAL file */
    uint64_t file_sz;                /* WAL file size */
    pthread_mutex_t lock;            /* Protect the WAL state */
    pthread_cond_t cond;             /* WAL cond variable */
    uint8_t cache_buf[A_WAL_BUF_SZ]; /* WAL buffer */
    uint32_t buf_off;                /* current write offset in WAL buffer */
    uint32_t holding_flush;          /* Number of thread holding the flush op from happening */
};

/* Cache buffer */
struct aura_db_cache_buf {
    char *data;
    uint32_t size;
    uint32_t cap;
    struct aura_db_bucket_entry hash_bucket[A_DB_HASH_BUCKET_CNT];
    uint8_t flags;
};

/* DB write cache structure */
struct aura_db_write_cache {
    struct aura_db_cache_buf bufs[2]; /* write buffers */
    uint32_t next_off;                /* Next insert offset in write cache */
    pthread_mutex_t lock;             /* cache mutex */
    pthread_cond_t swap_cond;         /* condition for swapping active buf */
    pthread_cond_t sync_cond;         /* cond for syncing inactive buf */
    uint8_t active_idx;               /* active buffer idx (0 or 1) */
    uint8_t write_idx;                /* Index of buffer to write */
};

/* DB read cache structure */
struct aura_db_read_cache {
    struct aura_db_cache_buf buf;
    pthread_rwlock_t rwlock;
};

/* Cache structure */
struct aura_db_cache {
    struct aura_db_write_cache wrt_cache;
    struct aura_db_read_cache read_cache;
};

/* commit structure */
struct aura_db_commit {
    txid_t tx_id;     /* Transaction ID */
    uint32_t rec_cnt; /* Record cnt for this transaction */
    uint8_t state;    /* Transaction state */
};

/* DB TX man structure */
struct aura_db_tx_ctx {
    txid_t next_id;
    uint64_t id_mask;
    pthread_mutex_t lock;
    pthread_cond_t wait;
    struct aura_db_tx_tab_ent tx_tab[A_DB_MAX_CONC_TX]; /* Active tx table */
    A_BITMAP_CREATE(64, tx_tab_map);
};

/* DB checkpoint ctx structure */
struct aura_db_checkpoint_ctx {
    pthread_mutex_t lock;
    pthread_cond_t cond;
    pthread_cond_t done;
    uint32_t nr_of_reqs; /* Number of checkpointer requests */
    uint32_t flags;
    bool ckpt_done; /* Used to indicate checkpoint is done */
    bool active;    /* Used to indicate checkpoint is active */
};

/* Background cache writer */
struct aura_db_bgwriter {
    pthread_mutex_t lock;
    pthread_cond_t cond;
    bool do_work; /* Used to tell bg writer to perform some work */
    int flags;
};

/* Log writer */
struct aura_db_log_writer {
    pthread_mutex_t lock;
    pthread_cond_t cond;
    int reqs; /* Number of requests for log writer */
    int flags;
};

/* Thread kind structure */
struct aura_db_th_kind {
    const char *desc;            /* Thread description */
    void *(*fn)(void *db);       /* Thread main routine */
    void (*shutdown_fn)(void *); /* Thread shutdown trigger routine */
};

/* Thread Key */
static pthread_key_t thread_key;
static pthread_once_t th_key_init_done = PTHREAD_ONCE_INIT;

/**
 * Database control structure
 */
struct aura_db_control {
    uint32_t magic;                                            /* Uinque system identifier to ensure correct versioning */
    int hash_algo;                                             /* Hash algorithm being used for key hashing */
    lsn_t last_rec_lsn;                                        /* Position of last record written to database */
    uint64_t record_cnt;                                       /* Nr of records */
    uint64_t file_size;                                        /* Data file size */
    uint64_t wasted_bytes;                                     /* total deleted records in the db */
    uint64_t created_ms;                                       /* Database creation time */
    uint64_t time_ms;                                          /* Time of last control update */
    uint64_t compact_time_ms;                                  /* Database last compaction time */
    uint32_t flags;                                            /* Flags */
    struct aura_db_checkpoint chkpt_copy;                      /* Copy of the latest checkpoint saved */
    struct aura_db_bucket_entry buckets[A_DB_HASH_BUCKET_CNT]; /* hash buckets */
    aura_db_state_t shutdown_state;                            /* Database state */
};

/*
 * Library's private representation of the database.
 */
typedef struct {
    struct aura_db_control control; /* Database control */
    int ctrl_file_fd;
    pthread_mutex_t ctrl_lock;                    /* Protect control structure */
    pthread_cond_t ctrl_cond;                     /* Wait on control busy */
    atomic_uint ref_cnt;                          /* Number of threads referencing the structure */
    struct aura_mem_ctx *mc;                      /* Memory context */
    struct aura_db_data main;                     /* Main DB context */
    struct aura_db_wal wal;                       /* WAL context */
    struct aura_db_cache cache;                   /* Cache */
    struct aura_db_th th_pool[A_DB_TH_CNT];       /* Thread pool*/
    struct aura_db_tx_ctx tx_ctx;                 /* Transaction context */
    struct aura_db_checkpoint_ctx checkpoint_ctx; /* Checkpointer thread attributes */
    struct aura_db_bgwriter bgwriter;             /* DB writer thread attributes */
    struct aura_db_log_writer wal_writer;         /* WAL writer thread attributes */
    lsn_t last_commit_offset;                     /* Last committed offset to WAL */
    const char *file_name;                        /* database file name */
    bool ctrl_busy;                               /* some operation being performed on db control */
    uint8_t state;                                /* Database state */
    bool shutdown;                                /* Signal for db to shutdown */
} AURA_DB;

/* Thread specific data structure */
struct aura_db_th_data {
    pid_t th_id;          /* Thread ID */
    txid_t tx_id;         /* Local transaction ID */
    int64_t glob_tx_idx;  /* Global Transaction ID */
    struct aura_db_tx tx; /* Transaction per thread */
    AURA_DB *db;          /* Pointer to global DB context */
};

/* Print wal record header */
static void a_db_wal_hhdr_dump(struct aura_db_wal_rec_hdr *);

/* Print record header */
static void a_db_rec_hdr_dump(struct aura_db_rec_hdr *);

/**/
static inline int a_db_log_flush(struct aura_db_wal *wal, int flags);

/**/
static inline void a_db_reset_th_data(struct aura_db_th_data *th_data);

/**/
static void a_db_write_cache_scan(struct aura_db_write_cache *cache);

/**/
static int a_db_replay(AURA_DB *db);

/**/
static int a_db_write_cache_append(AURA_DB *db, struct aura_db_rec_hdr *rec_hdr,
                                   struct aura_iovec *key, struct aura_iovec *data);

/**/
static int a_db_write_cache_flush(AURA_DB *db, int flags);

/**/
static void *a_db_checkpointer(void *arg);

/**/
static inline void a_db_request_checkpoint(struct aura_db_checkpoint_ctx *c, int flags);

/**
 * Get record size  8-byte aligned
 */
static inline struct aura_db_rec_len a_get_db_record_len(size_t key_len, size_t data_len) {
    struct aura_db_rec_len len;

    len.raw_len = sizeof(struct aura_db_rec_hdr) + key_len + data_len;
    len.aligned_len = A_ALIGN(len.raw_len, sizeof(void *));
    return len;
}

/* Calculate key hash */
static inline uint32_t a_fnv1a_hash(uint32_t bucket_cnt, ns_t namespace, struct aura_iovec *key) {
    uint32_t hash, hash_val;

    hash_val = FNV1_32A_INIT;
    hash_val ^= (uint32_t)namespace;
    hash = fnv_32a_buf((void *)key->base, key->len, hash_val);
    return hash & A_DB_HASH_BUCKET_MASK;
}

/**
 * Save db meta data
 * Pass an immutable memory to this function
 */
static inline ssize_t a_db_meta_write(int fd, void *meta, size_t len) {
    struct iovec iov[2];

    if (lseek(fd, 0, SEEK_SET) < 0)
        return -1;

    if (write(fd, meta, len) != len)
        return -1;

    return 0;
}

/**
 * Read db meta data
 * This is called only on startup for now
 * So there may not be need to lock!
 */
static inline ssize_t a_db_meta_read(int fd, void *meta, size_t len) {
    struct iovec iov[2];

    if (lseek(fd, 0, SEEK_SET) < 0)
        return -1;

    if (read(fd, meta, len) != len)
        return -1;

    return 0;
}

/**
 * Destroy thread specific resources
 */
static void a_th_db_data_destroy(void *_data) {
    struct aura_db_th_data *data = _data;

    if (data) {
        a_db_reset_th_data(data);
        free(data);
    }
}

/**
 * Initialize thread key for thread
 * specific data
 */
static void a_db_th_key_init(void) {
    pthread_key_create(&thread_key, a_th_db_data_destroy);
}

/* Log writer thread cleanup function */
static void a_db_wal_writer_th_cleanup(void *arg) {
    AURA_DB *db = arg;

    db->th_pool[A_DB_THREAD_WAL_WRITER].status = A_DB_BG_TH_STOPPED;
    atomic_fetch_sub(&db->ref_cnt, 1);
}

/**
 * Log file writer
 */
static void *a_db_wal_writer_routine(void *arg) {
    AURA_DB *db = arg;
    struct timespec ts;
    bool shutdown, timedout;
    int rv;

    /**
     * Register thread using DB
     * Add reference count on DB
     */
    atomic_store(&(db->th_pool[A_DB_THREAD_WAL_WRITER].status), A_DB_BG_TH_RUNNING);
    atomic_fetch_add(&db->ref_cnt, 1);
    pthread_cleanup_push(a_db_wal_writer_th_cleanup, arg);

    pthread_barrier_wait(&barrier);

    shutdown = false;
    for (;;) {
        timedout = false;
        pthread_mutex_lock(&db->wal_writer.lock);
        while (db->wal_writer.reqs == 0) {
            ts.tv_sec = time(NULL) + A_DB_WAL_WRITER_INTERVAL;
            ts.tv_nsec = 0;

            rv = pthread_cond_timedwait(&db->wal_writer.cond, &db->wal_writer.lock, &ts);
            if (rv != 0 && rv != ETIMEDOUT)
                goto out;

            if (rv == ETIMEDOUT)
                timedout = true;

            break;
        }

        if (db->wal_writer.flags & A_DB_THREAD_WAL_WRITER_SHUTDOWN)
            shutdown = true;
        db->wal_writer.reqs = 0;
        pthread_mutex_unlock(&db->wal_writer.lock);

        /* Perform flush if needed. */
        pthread_mutex_lock(&db->wal.lock);
        while (db->wal.holding_flush > 0)
            pthread_cond_wait(&db->wal.cond, &db->wal.lock);

        rv = a_db_log_flush(&db->wal, A_DB_LOG_WRITER_TIMED);
        pthread_mutex_unlock(&db->wal.lock);

        if (rv < 0 || shutdown) {
            break;
        }

        /* Request checkpoint */
        if (rv == 1) {
            a_db_request_checkpoint(&db->checkpoint_ctx, A_DB_CHECKPOINT_LOG);
        }
    }

out:
    /* Run cleanup */
    pthread_cleanup_pop(1);
    return NULL;
}

static void a_db_wal_writer_shutdown(void *arg) {
    AURA_DB *db = arg;
    pthread_mutex_lock(&db->wal_writer.lock);
    db->wal_writer.flags |= A_DB_THREAD_WAL_WRITER_SHUTDOWN;
    ++db->wal_writer.reqs;
    pthread_cond_signal(&db->wal_writer.cond);
    pthread_mutex_unlock(&db->wal_writer.lock);
}

/* Background db writer thread cleanup function */
static void a_db_bg_writer_th_cleanup(void *arg) {
    AURA_DB *db = arg;

    db->th_pool[A_DB_THREAD_BG_WRITER].status = A_DB_BG_TH_STOPPED;
    atomic_fetch_sub(&db->ref_cnt, 1);
}

static void *a_db_bg_writer_routine(void *arg) {
    AURA_DB *db = arg;
    struct timespec ts;
    bool shutdown, timedout = false;
    int rv;

    /**
     * Register thread using DB
     */
    atomic_store(&(db->th_pool[A_DB_THREAD_BG_WRITER].status), A_DB_BG_TH_RUNNING);
    atomic_fetch_add(&db->ref_cnt, 1);
    pthread_cleanup_push(a_db_bg_writer_th_cleanup, arg);

    pthread_barrier_wait(&barrier);
    shutdown = false;
    for (;;) {
        pthread_mutex_lock(&db->bgwriter.lock);
        while (db->bgwriter.do_work == false) {
            ts.tv_sec = time(NULL) + A_DB_BG_WRITER_INTERVAL;
            ts.tv_nsec = 0;

            rv = pthread_cond_timedwait(&db->bgwriter.cond, &db->bgwriter.lock, &ts);
            if (rv != 0 && rv != ETIMEDOUT)
                goto out;

            if (rv == ETIMEDOUT)
                timedout = true;

            break;
        }

        if (db->bgwriter.flags & A_DB_THREAD_BG_WRITER_SHUTDOWN)
            shutdown = true;

        db->bgwriter.do_work = false;
        pthread_mutex_unlock(&db->bgwriter.lock);

        if (a_db_write_cache_flush(db, 0) < 0)
            break;

        if (shutdown) {
            break;
        }
    }

out:
    pthread_cleanup_pop(1);
    return NULL;
}

static void a_db_bg_writer_shutdown(void *arg) {
    AURA_DB *db = arg;
    pthread_mutex_lock(&db->bgwriter.lock);
    db->bgwriter.flags |= A_DB_THREAD_BG_WRITER_SHUTDOWN;
    db->bgwriter.do_work = true;
    pthread_cond_signal(&db->bgwriter.cond);
    pthread_mutex_unlock(&db->bgwriter.lock);
}

static void a_db_checkpointer_shutdown(void *arg) {
    AURA_DB *db = arg;
    pthread_mutex_lock(&db->checkpoint_ctx.lock);
    ++db->checkpoint_ctx.nr_of_reqs;
    db->checkpoint_ctx.flags |= A_DB_CHECKPOINT_SHUTDOWN;
    pthread_cond_signal(&db->checkpoint_ctx.cond);
    pthread_mutex_unlock(&db->checkpoint_ctx.lock);
}

static void *a_db_compactor(void *arg) {
    AURA_DB *db = arg;
    return NULL;
}

static void a_db_compactor_shutdown(void *arg) {
    /**/
}

static struct aura_db_th_kind a_db_thread_kinds[] = {
#define A_THREAD_KIND(type, desc, fn, shutdown_fn) [type] = {desc, fn, shutdown_fn}
  A_THREAD_KIND(A_DB_THREAD_WAL_WRITER, "wal writer", a_db_wal_writer_routine, a_db_wal_writer_shutdown),
  A_THREAD_KIND(A_DB_THREAD_BG_WRITER, "bg writer", a_db_bg_writer_routine, a_db_bg_writer_shutdown),
  A_THREAD_KIND(A_DB_THREAD_CHECKPOINTER, "check pointer", a_db_checkpointer, a_db_checkpointer_shutdown),
  A_THREAD_KIND(A_DB_THREAD_COMPACTOR, "compactor", a_db_compactor, a_db_compactor_shutdown),
#undef A_THREAD_KIND
};

/* Start background worker thread of type = @type */
static int a_db_start_bg_thread(AURA_DB *db, aura_db_bg_worker_t type) {
    struct aura_db_th *thread;

    thread = &db->th_pool[type];
    thread->wrk_type = type;
    thread->fn = a_db_thread_kinds[type].fn;
    thread->shutdown_fn = a_db_thread_kinds[type].shutdown_fn;

    if (pthread_create(&thread->handle, NULL, thread->fn, (void *)db) != 0) {
        return -1;
    }

    return 0;
}

/**
 * Initialize control file and structure
 */
static int a_db_ctrl_init(AURA_DB *db, const char *ctrl_file, int oflag, int mode, bool init) {
    struct aura_db_control *ctrl = &db->control;
    struct stat s_buf;

    db->ctrl_file_fd = open(ctrl_file, oflag, mode);
    if (db->ctrl_file_fd < 0)
        return -1;

    if (fstat(db->ctrl_file_fd, &s_buf) < 0) {
        close(db->ctrl_file_fd);
        return -1;
    }

    /* */
    if (s_buf.st_size == 0) {
        ctrl->magic = A_DB_MAGIC;
        ctrl->hash_algo = A_FNV1A_HASH_ALGO;
        ctrl->created_ms = aura_now_ms(CLOCK_MONOTONIC);
        ctrl->flags = 0;
        ctrl->compact_time_ms = 0;
        ctrl->file_size = 0;
        ctrl->record_cnt = 0;
        ctrl->last_rec_lsn = 0;
        /* Fake we shutdown cleanly for the case of DB initialization, so we don't run recovery */
        ctrl->shutdown_state = init ? A_DB_STATE_SHUTDOWN : 0;

        last_checkpoint_lsn = 0;
        last_important_lsn = 0;

        for (int i = 0; i < A_DB_HASH_BUCKET_CNT; ++i)
            ctrl->buckets[i].head_off = UINT64_MAX;

        if (a_db_meta_write(db->ctrl_file_fd, ctrl, sizeof(*ctrl)) < 0) {
            close(db->ctrl_file_fd);
            return -1;
        }
    } else if (s_buf.st_size != sizeof(*ctrl)) {
        app_debug(true, 0, "Possibly corrupted control file");
        return -1;
    } else {
        if (a_db_meta_read(db->ctrl_file_fd, ctrl, sizeof(*ctrl)) < 0) {
            close(db->ctrl_file_fd);
            return -1;
        }

        last_checkpoint_lsn = db->control.chkpt_copy.rec_lsn;
        last_important_lsn = last_checkpoint_lsn;
    }

    if (pthread_mutex_init(&db->ctrl_lock, NULL) != 0) {
        close(db->ctrl_file_fd);
        return -1;
    }

    if (pthread_cond_init(&db->ctrl_cond, NULL) != 0) {
        pthread_mutex_destroy(&db->ctrl_lock);
        close(db->ctrl_file_fd);
        return -1;
    }

    return 0;
}

static void a_db_ctrl_destroy(AURA_DB *db) {
    pthread_mutex_destroy(&db->ctrl_lock);
    pthread_cond_destroy(&db->ctrl_cond);
    close(db->ctrl_file_fd);
}

/**
 * Initialize database file and structure
 */
static int a_db_data_init(struct aura_db_data *data, const char *data_file, int oflag, int mode) {
    struct stat s_buf;

    /* database file */
    data->fd = open(data_file, oflag, mode);
    if (data->fd < 0) {
        return -1;
    }

    if (pthread_mutex_init(&data->lock, NULL) != 0) {
        close(data->fd);
        return -1;
    }

    return 0;
}

static void a_db_data_destroy(struct aura_db_data *data) {
    pthread_mutex_destroy(&data->lock);
    close(data->fd);
}

/**
 * Initialize Log structure and Log file
 */
static int a_db_wal_init(struct aura_db_wal *wal, const char *wal_file, int oflag, int mode) {
    struct stat s_buf;

    /* database file */
    wal->fd = open(wal_file, oflag, mode);
    if (wal->fd < 0)
        return -1;

    if (pthread_mutex_init(&wal->lock, NULL) != 0) {
        close(wal->fd);
        return -1;
    }

    if (pthread_cond_init(&wal->cond, NULL) != 0) {
        close(wal->fd);
        pthread_mutex_destroy(&wal->lock);
        return -1;
    }

    if (fstat(wal->fd, &s_buf) < 0) {
        close(wal->fd);
        pthread_mutex_destroy(&wal->lock);
        pthread_cond_destroy(&wal->cond);
        return -1;
    }

    wal->write_lsn = s_buf.st_size;
    wal->file_sz = s_buf.st_size;
    wal->holding_flush = 0;
    wal->buf_off = 0;
    glob_flushed_lsn = 0;

    return 0;
}

static void a_db_log_destroy(struct aura_db_wal *wal) {
    pthread_mutex_destroy(&wal->lock);
    pthread_cond_destroy(&wal->cond);
    close(wal->fd);
}

/**
 * Initialize DB cache structure
 */
static int a_db_init_cache(struct aura_db_cache *cache, uint32_t write_cache_sz, uint32_t read_cache_sz) {
    struct aura_db_write_cache *wrt_cache;
    struct aura_db_read_cache *rd_cache;

    memset(cache, 0, sizeof(*cache));

    /* setup write cache */
    wrt_cache = &cache->wrt_cache;

    wrt_cache->active_idx = 0;
    wrt_cache->write_idx = 0;
    for (int i = 0; i < 2; ++i) {
        wrt_cache->bufs[i].data = calloc(1, write_cache_sz);
        if (!(wrt_cache->bufs[i].data)) {
            if (i == 1)
                free(cache->wrt_cache.bufs[i].data);
            return -1;
        }

        wrt_cache->bufs[i].cap = write_cache_sz;
        for (int j = 0; j < A_DB_HASH_BUCKET_CNT; ++j)
            wrt_cache->bufs[i].hash_bucket[j].head_off = UINT64_MAX;
    }

    /* setup read cache */
    rd_cache = &cache->read_cache;
    if (pthread_rwlock_init(&rd_cache->rwlock, NULL) != 0)
        goto err_wrt_cache;

    rd_cache->buf.data = calloc(1, read_cache_sz);
    if (!rd_cache->buf.data) {
        pthread_rwlock_destroy(&rd_cache->rwlock);
        goto err_wrt_cache;
    }

    rd_cache->buf.cap = read_cache_sz;

    /**
     * A cache offset starts at zero making zero
     * a valid offset, therefore, we initialize
     * hash entries to 'UINT64_MAX'
     */
    for (int i = 0; i < A_DB_HASH_BUCKET_CNT; ++i)
        rd_cache->buf.hash_bucket[i].head_off = UINT64_MAX;

    if (pthread_mutex_init(&wrt_cache->lock, NULL) != 0)
        goto err_rd_cache;

    if (pthread_cond_init(&wrt_cache->swap_cond, NULL) != 0)
        goto err_wrt_lock;

    if (pthread_cond_init(&wrt_cache->sync_cond, NULL) != 0) {
        pthread_mutex_destroy(&wrt_cache->lock);
        goto err_wrt_lock;
    }

    return 0;

err_wrt_lock:
    pthread_mutex_destroy(&wrt_cache->lock);

err_rd_cache:
    pthread_rwlock_destroy(&rd_cache->rwlock);
    free(rd_cache->buf.data);

err_wrt_cache:
    for (int i = 0; i < 2; ++i)
        free(cache->wrt_cache.bufs[i].data);

    return -1;
}

/* Destroy DB cache */
static void a_db_destroy_cache(struct aura_db_cache *cache) {
    pthread_cond_destroy(&cache->wrt_cache.sync_cond);
    pthread_cond_destroy(&cache->wrt_cache.swap_cond);
    pthread_mutex_destroy(&cache->wrt_cache.lock);

    for (int i = 0; i < 2; ++i)
        free(cache->wrt_cache.bufs[i].data);

    pthread_rwlock_destroy(&cache->read_cache.rwlock);
    free(cache->read_cache.buf.data);
}

/* Initilize tx context */
static int a_db_tx_ctx_init(struct aura_db_tx_ctx *tx_ctx) {
    memset(tx_ctx, 0, sizeof(*tx_ctx));
    tx_ctx->id_mask = A_DB_MAX_CONC_TX - 1;

    if (pthread_mutex_init(&tx_ctx->lock, NULL) != 0)
        return -1;

    if (pthread_cond_init(&tx_ctx->wait, NULL) != 0) {
        pthread_mutex_destroy(&tx_ctx->lock);
        return -1;
    }

    return 0;
};

/* Destroy tx context */
static void a_db_tx_ctx_destroy(struct aura_db_tx_ctx *tx_ctx) {
    pthread_mutex_destroy(&tx_ctx->lock);
    pthread_cond_destroy(&tx_ctx->wait);
}

/* Initialize checkpoint context */
static int a_db_checkpoint_ctx_init(struct aura_db_checkpoint_ctx *c) {
    if (pthread_mutex_init(&c->lock, NULL) != 0)
        return -1;

    if (pthread_cond_init(&c->cond, NULL) != 0) {
        pthread_mutex_destroy(&c->lock);
        return -1;
    }

    if (pthread_cond_init(&c->done, NULL) != 0) {
        pthread_cond_destroy(&c->cond);
        pthread_mutex_destroy(&c->lock);
        return -1;
    }

    return 0;
}

/* Destroy checkpoint context */
static void a_db_checkpoint_ctx_destroy(struct aura_db_checkpoint_ctx *c) {
    pthread_cond_destroy(&c->cond);
    pthread_cond_destroy(&c->done);
    pthread_mutex_destroy(&c->lock);
}

/* Initialize log writer context */
static int a_db_log_writer_ctx_init(struct aura_db_log_writer *lw) {
    if (pthread_mutex_init(&lw->lock, NULL) != 0)
        return -1;

    if (pthread_cond_init(&lw->cond, NULL) != 0) {
        pthread_mutex_destroy(&lw->lock);
        return -1;
    }

    return 0;
}

/* Destroy log writer context */
static void a_db_log_writer_ctx_destroy(struct aura_db_log_writer *lw) {
    pthread_mutex_destroy(&lw->lock);
    pthread_cond_destroy(&lw->cond);
}

/* Initialize background writer context */
static int a_db_bg_writer_ctx_init(struct aura_db_bgwriter *bg) {
    if (pthread_mutex_init(&bg->lock, NULL) != 0)
        return -1;

    if (pthread_cond_init(&bg->cond, NULL) != 0) {
        pthread_mutex_destroy(&bg->lock);
        return -1;
    }

    return 0;
}

/* Destroy background writer context */
static void a_db_bg_writer_ctx_destroy(struct aura_db_bgwriter *bg) {
    pthread_mutex_destroy(&bg->lock);
    pthread_cond_destroy(&bg->cond);
}

/* Update database state */
static inline void a_db_update_state(AURA_DB *db, int state) {
    atomic_store(&db->state, state);
}

static AURA_DB *a_db_open(struct aura_mem_ctx *mc, const char *db_path, int oflag, int mode,
                          uint32_t write_cache_sz, uint32_t read_cache_sz) {
    AURA_DB *db;
    struct stat s_buf;
    char ctrl_file[A_DB_MAX_FILE_PATH_LEN + 32] = {0};
    char data_file[A_DB_MAX_FILE_PATH_LEN + 32] = {0};
    char wal_file[A_DB_MAX_FILE_PATH_LEN + 32] = {0};
    bool init;
    int rv;

    snprintf(ctrl_file, sizeof(ctrl_file), "%s%s", db_path, AURA_DB_CONTROL_FILE);
    snprintf(data_file, sizeof(data_file), "%s%s", db_path, AURA_DB_DATA_FILE);
    snprintf(wal_file, sizeof(wal_file), "%s%s", db_path, AURA_DB_WAL_FILE);

    /* Allocate a DB structure, and the buffers it needs. */
    db = calloc(1, sizeof(AURA_DB));
    if (!db)
        return NULL;

    // db->file_name = strndup(db_file, strlen(db_file));
    // if (!db->file_name) {
    //     free(db);
    //     return NULL;
    // }
    db->mc = mc;
    db->shutdown = false;
    a_db_update_state(db, A_DB_STATE_STARTUP);

    /* Check control file */
    init = false;
    if (stat(ctrl_file, &s_buf) < 0) {
        if (errno != ENOENT)
            return NULL;
        init = true;
    }

    if (init) {
        oflag |= O_CREAT | O_TRUNC | O_EXCL;
    }

    /* Setup control */
    if (a_db_ctrl_init(db, ctrl_file, oflag, mode, init) < 0)
        goto err_main;

    /* Setup data */
    if (a_db_data_init(&db->main, data_file, oflag, mode) < 0)
        goto err_ctrl;

    /** @todo: use different mode for WAL file */
    /* Setup wal */
    if (a_db_wal_init(&db->wal, wal_file, oflag, mode) < 0) {
        goto err_log;
    }

    /* Setup cache */
    if (a_db_init_cache(&db->cache, write_cache_sz, read_cache_sz) < 0) {
        goto err_cache;
    }

    /* Setup transaction context */
    if (a_db_tx_ctx_init(&db->tx_ctx) < 0) {
        goto err_tx;
    }

    /* Checkpointer */
    if (a_db_checkpoint_ctx_init(&db->checkpoint_ctx) < 0)
        goto err_chkpt;

    /* Log writer */
    if (a_db_log_writer_ctx_init(&db->wal_writer) < 0)
        goto err_logwrt;

    /* Bg writer */
    if (a_db_bg_writer_ctx_init(&db->bgwriter) < 0)
        goto err_bgwrt;

    return db;

err_bgwrt:
    a_db_log_writer_ctx_destroy(&db->wal_writer);

err_logwrt:
    a_db_checkpoint_ctx_destroy(&db->checkpoint_ctx);

err_chkpt:
    a_db_tx_ctx_destroy(&db->tx_ctx);

err_tx:
    a_db_destroy_cache(&db->cache);

err_cache:
    a_db_log_destroy(&db->wal);

err_log:
    a_db_data_destroy(&db->main);

err_ctrl:
    a_db_ctrl_destroy(db);

err_main:
    free((void *)db->file_name);
    free(db);
    return NULL;
}

/*
 * Open or create a database.  Structured kind of similar to open(2).
 */
AURA_DBHANDLE aura_db_open(struct aura_mem_ctx *mc, const char *db_path) {
    AURA_DB *db;

    db = a_db_open(
      mc,
      db_path,
      O_RDWR,
      A_DB_FILE_MODE,
      A_DB_WRITE_CACHE_BUF_SZ,
      A_DB_READ_CACHE_BUF_SZ);
    if (!db)
        return NULL;

    /* Check if we should boot in recovery */
    if (db->control.shutdown_state != A_DB_STATE_SHUTDOWN) {
        if (a_db_replay(db) < 0) {
            app_debug(true, 0, "Failed to boot recovery");
            return NULL;
        }
    }

    a_db_update_state(db, A_DB_STATE_RUNNING);

    /* Initialize pthread key for thread specific data */
    pthread_once(&th_key_init_done, a_db_th_key_init);

    /**
     * We would want to wait for all threads to start before
     * we return, this is because we would want routines
     * that depend on some particular threads starting do
     * error as a result of the thread missing on the entity
     * the thread sets up is still uninitialized
     */
    pthread_barrier_init(&barrier, NULL, A_DB_NR_THREADS + 1); /* +1 for main*/

    a_db_start_bg_thread(db, A_DB_THREAD_BG_WRITER);
    a_db_start_bg_thread(db, A_DB_THREAD_WAL_WRITER);
    a_db_start_bg_thread(db, A_DB_THREAD_CHECKPOINTER);

    /**
     * We wait for all threads to start before returning
     */
    pthread_barrier_wait(&barrier);

    /* Open for business */
    return db;
}

void _a_db_close(AURA_DB *db) {
    a_db_data_destroy(&db->main);
    a_db_log_destroy(&db->wal);
    a_db_destroy_cache(&db->cache);
    a_db_checkpoint_ctx_destroy(&db->checkpoint_ctx);
    a_db_log_writer_ctx_destroy(&db->wal_writer);
    a_db_bg_writer_ctx_destroy(&db->bgwriter);
}

/**
 * Wait for active transactions to finish
 */
static void a_db_finalize_active_transactions(AURA_DB *db) {
    struct timespec ts;
    uint64_t timeout;
    int rv;

    pthread_mutex_lock(&db->tx_ctx.lock);
    aura_now_ts(&ts, CLOCK_MONOTONIC);
    ts.tv_sec = time(NULL) + 1;
    ts.tv_sec = 0;
    timeout = ts.tv_sec;

    while (aura_bitmap_find_next_bit(db->tx_ctx.tx_tab_map, 0, A_DB_MAX_CONC_TX) != A_DB_MAX_CONC_TX) {
        rv = pthread_cond_timedwait(&db->tx_ctx.wait, &db->tx_ctx.lock, &ts);
        if (rv == ETIMEDOUT)
            break;

        /**
         * In the case where a signal happens to fire at
         * same time as the timeout. The signal takes
         * precedence and the timeout is lost. So we do a manual
         * check for that case.
         */
        if (time(NULL) - timeout > A_DB_GRACEFUL_SHUTDOWN_TIMEOUT)
            break;
    }

    /* Abort current active transactions if timeout */
    if (aura_bitmap_find_next_bit(db->tx_ctx.tx_tab_map, 0, A_DB_MAX_CONC_TX) != A_DB_MAX_CONC_TX) {
        uint64_t i = aura_bitmap_find_next_bit(db->tx_ctx.tx_tab_map, 0, A_DB_MAX_CONC_TX);
        for (; i != A_DB_MAX_CONC_TX;) {
            db->tx_ctx.tx_tab[i].abort = true;
            i = aura_bitmap_find_next_bit(db->tx_ctx.tx_tab_map, i, A_DB_MAX_CONC_TX);
        }
    }
    pthread_mutex_unlock(&db->tx_ctx.lock);

    /* Freeze anymore new work requests to the db */
    a_db_update_state(db, A_DB_STATE_STORAGE_SYNC);
}

/* Request a checkpoint */
static inline void a_db_request_checkpoint(struct aura_db_checkpoint_ctx *c, int flags) {
    pthread_mutex_lock(&c->lock);
    c->ckpt_done = false;
    ++c->nr_of_reqs;
    c->flags |= flags;
    pthread_cond_signal(&c->cond);
    pthread_mutex_unlock(&c->lock);
}

/*
 * Close and destroy DB resources
 */
void aura_db_close(AURA_DBHANDLE _db) {
    AURA_DB *db = _db;
    uint32_t idx;
    int shutdown_mode = A_DB_SHUTDOWN_GRACEFUL;
    int timeout;

    a_db_update_state(db, A_DB_STATE_QUIESCING);

    /* Allow active transactions to finish */
    if (shutdown_mode == A_DB_SHUTDOWN_GRACEFUL) {
        a_db_finalize_active_transactions(db);
    }

    /* shutdown background writer thread */
    db->th_pool[A_DB_THREAD_BG_WRITER].shutdown_fn(db);

    /* shutdown wal writer  thread */
    db->th_pool[A_DB_THREAD_WAL_WRITER].shutdown_fn(db);

    /**
     * Run final checkpoint
     * Checkpointer caches and forces syncing manually.
     * It also updates the control file, so order of shutting
     * down the other threads should not affect the db.
     */
    a_db_request_checkpoint(&db->checkpoint_ctx, A_DB_CHECKPOINT_SHUTDOWN);

    /* Wait for checkpoint */
    pthread_mutex_lock(&db->checkpoint_ctx.lock);
    while (!db->checkpoint_ctx.ckpt_done) {
        pthread_cond_wait(&db->checkpoint_ctx.done, &db->checkpoint_ctx.lock);
    }
    pthread_mutex_unlock(&db->checkpoint_ctx.lock);

    /* Stop workers */
    // for (int i = 0; i < A_DB_TH_CNT; ++i)
    //     if (db->th_pool[i].status == A_DB_BG_TH_RUNNING) {
    //         db->th_pool[i].shutdown_fn(db);
    //     }

    while (db->ref_cnt > 0) {
        sleep(0.25);
    }

out:
    _a_db_close(db);
    pthread_barrier_destroy(&barrier);
    // free((void *)db->file_name);
    free(_db);
}

enum {
    A_DB_REQ_OK,
    A_DB_REQ_REJECTED,
    A_DB_REQ_ABORT
};
/**
 * Determine if the database can accept a
 * new work request
 */
static int a_db_can_accept_req(AURA_DB *db, int64_t tx_id, int32_t tx_idx) {
    struct aura_db_tx_tab_ent *g_tx;
    int db_state = atomic_load(&db->state);
    int rv;

    switch (db_state) {
    case A_DB_STATE_RUNNING:
        return A_DB_REQ_OK;

    case A_DB_STATE_QUIESCING:
        /* Reject brand new work */
        if (tx_id == -1 || tx_id == -1)
            return A_DB_REQ_REJECTED;

        pthread_mutex_lock(&db->tx_ctx.lock);
        g_tx = &db->tx_ctx.tx_tab[tx_idx];
        /* This invariant must hold unless the code becomes flawed */
        A_BUG_ON_2(tx_id != g_tx->id, true);

        if (g_tx->abort)
            rv = A_DB_REQ_ABORT;
        else if (g_tx->state == A_DB_TX_IN_PROGRESS)
            rv = A_DB_REQ_OK;
        else
            rv = A_DB_REQ_REJECTED;
        pthread_mutex_unlock(&db->tx_ctx.lock);
        return rv;

    default:
        return A_DB_REQ_REJECTED;
    }
}

/**
 * Reset thread specific data for a new context
 */
static inline void a_db_reset_th_data(struct aura_db_th_data *th_data) {
    struct aura_sliding_buf *buf;
    th_data->glob_tx_idx = -1;

    if (th_data->tx.flags & A_DB_TX_FL_MR) {
        // while (!aura_list_is_empty(&th_data->tx.buf_list)) {
        //     /* Destroy chained sliding buf */
        //     a_list_dequeue(buf, &th_data->tx.buf_list, allocated.link);
        //     aura_sliding_buf_destroy(buf);
        // }
        aura_sliding_buf_destroy(&th_data->tx.priv_buf);
    }

    th_data->tx.rdata_cnt = 0;
    th_data->tx.reserved_off = 0;
    th_data->tx.rec_cnt = 0;
    th_data->tx.rec_len = 0;
    th_data->tx.flags = A_DB_TX_FL_NIL;
    th_data->tx.id = -1;
    th_data->tx.state = A_DB_TX_NIL;
}

/** Construct DB record header */
static inline int64_t a_db_rec_hdr_init(AURA_DB *db, struct aura_db_rec_hdr *rec_hdr,
                                        ns_t namespace, schema_id_t schema_id, txid_t tx_id,
                                        lsn_t prev_tx_rec, struct aura_iovec *key,
                                        struct aura_iovec *data, uint16_t flags) {
    uint32_t hash, old_head;
    struct aura_iovec checksum;

    hash = a_fnv1a_hash(A_DB_HASH_BUCKET_CNT, namespace, key);
    /** @todo: acquire lock to read old_head, no need since I update it when writing record */
    // old_head = atomic_load(&(db->main.db_hdr.buckets[hash].head_off));

    rec_hdr->magic = A_DB_REC_MAGIC;
    rec_hdr->ns = namespace;
    rec_hdr->flags = flags;
    rec_hdr->schema_id = schema_id;
    rec_hdr->prev_off = old_head;
    rec_hdr->tx_id = tx_id;
    rec_hdr->prev_tx_rec_off = prev_tx_rec;
    rec_hdr->timestamp_ms = aura_now_ms(CLOCK_MONOTONIC);
    rec_hdr->key_len = key->len;
    rec_hdr->hash = hash;

    if (data) {
        rec_hdr->data_len = data->len;
        rec_hdr->rec_len = a_get_db_record_len(key->len, data->len);
        checksum.base = rec_hdr->checksum;

        if (aura_calculate_digest(data, &checksum) < 0) {
            app_debug(true, 0, "a_db_init_rec_hdr: aura_calculate_digest error");
            return -1;
        }
    } else {
        rec_hdr->data_len = 0;
        rec_hdr->rec_len = a_get_db_record_len(key->len, 0);
    }

    return 0;
}

/* Initialize log record header */
static inline void a_db_wal_rec_hdr_init(struct aura_db_wal_rec_hdr *wal_rec_hdr, int wal_type,
                                         struct aura_db_rec_hdr *rec_hdr, uint8_t db_op) {
    wal_rec_hdr->type = wal_type;
    wal_rec_hdr->tx_id = rec_hdr->tx_id;
    wal_rec_hdr->op = db_op;
    wal_rec_hdr->rec_len = A_ALIGN(sizeof(*wal_rec_hdr) + rec_hdr->rec_len.aligned_len, 8);
    wal_rec_hdr->magic = 0;
}

/* Get slot in active transaction table */
static inline void a_db_tx_tab_get_active_slot_idx(AURA_DB *db, uint64_t *idx, uint64_t *tx_id) {
    uint64_t _idx;

    pthread_mutex_lock(&db->tx_ctx.lock);

    _idx = aura_bitmap_find_next_empty_bit(db->tx_ctx.tx_tab_map, 0, A_DB_MAX_CONC_TX);
    while (_idx == A_DB_MAX_CONC_TX) {
        pthread_cond_wait(&db->tx_ctx.wait, &db->tx_ctx.lock);
        /** @todo: check tx timeout */
        _idx = aura_bitmap_find_next_bit(db->tx_ctx.tx_tab_map, 0, A_DB_MAX_CONC_TX);
    }

    aura_bitmap_set_bit(_idx, db->tx_ctx.tx_tab_map);
    /* Store slot index and tx id */
    *idx = _idx;
    *tx_id = db->tx_ctx.next_id;

    db->tx_ctx.next_id = (db->tx_ctx.next_id + 1) & db->tx_ctx.id_mask;

    pthread_mutex_unlock(&db->tx_ctx.lock);
}

/**
 * Assign a true transaction ID for this
 * transaction. Previous transaction ID
 * was a virtual ID from the specific thread
 */
static inline void a_db_tx_promote(AURA_DB *db, struct aura_db_th_data *th_data) {
    struct aura_db_tx_tab_ent *e;
    struct aura_db_tx *tx;
    uint64_t idx, tx_id;

    A_BUG_ON_2(th_data->glob_tx_idx != -1, true);
    tx = &th_data->tx;
    A_BUG_ON_2((tx->flags & A_DB_TX_FL_VIRT) == 0, true);

    a_db_tx_tab_get_active_slot_idx(db, &idx, &tx_id);
    e = &db->tx_ctx.tx_tab[idx];
    e->thread_id = th_data->th_id;
    e->state = tx->state;
    e->id = tx_id;

    th_data->glob_tx_idx = idx;
    /* remove virtual tx flag */
    tx->flags = tx->flags & ~A_DB_TX_FL_VIRT;
    tx->id = tx_id;
}

/**
 * Resets cache buffer.
 */
static inline void a_db_reset_cache_buf(struct aura_db_cache_buf *buf) {
    buf->size = 0;
    buf->flags = 0;
    memset(buf->data, 0, buf->cap);
    for (int i = 0; i < A_DB_HASH_BUCKET_CNT; ++i)
        buf->hash_bucket[i].head_off = UINT64_MAX;
}

/**
 * Add record to read cache
 * Cache write lock must be held before
 * calling this function
 */
static int a_db_read_cache_insert(struct aura_db_read_cache *cache, struct aura_db_rec_hdr *rec_hdr,
                                  struct aura_iovec *key, struct aura_iovec *data) {
    uint64_t next_append_off;
    uint64_t prev_rec_cache_off;

    /**
     * Because the hash bucket chain is updated on
     * checkpoint, this records previous off in the chain
     * is correctly updated before adding it to the
     * permanent DB. Since we always read the correct prev off
     * from file, we can use the cache records cache offset to
     * create a correct cache chain as this will not touch the real
     * file prev off associated with this record.
     */
    prev_rec_cache_off = cache->buf.hash_bucket[rec_hdr->hash].head_off;
    next_append_off = cache->buf.size + rec_hdr->rec_len.aligned_len;

    /**
     * Bypass huge records that can not all fit in cache
     */
    if (rec_hdr->rec_len.aligned_len > A_DB_CACHE_SIZE) {
        return 0;
    }

    /**
     * If cummulative records can't fit in cache
     * Simplest way is to reset cache currently.
     */
    if (next_append_off > A_DB_CACHE_SIZE) {
        a_db_reset_cache_buf(&cache->buf);
        /**
         * If cache is reset, the previous record
         * should point to an empty slot.
         */
        prev_rec_cache_off = UINT64_MAX;
    }

    char *write_ptr = cache->buf.data + cache->buf.size;
    memcpy(write_ptr, rec_hdr, sizeof(*rec_hdr));

    /* key offset */
    write_ptr += sizeof(*rec_hdr);
    memcpy(write_ptr, key->base, rec_hdr->key_len);

    if (data) {
        /* data offset */
        write_ptr += rec_hdr->key_len;
        memcpy(write_ptr, data->base, data->len);
    }

    // rec_hdr->prev_off = prev_rec_off;
    rec_hdr->prev_cache_off = prev_rec_cache_off;
    cache->buf.hash_bucket[rec_hdr->hash].head_off = cache->buf.size;
    cache->buf.size += rec_hdr->rec_len.aligned_len;

    return 0;
}

/**
 * Reserve space in the WAL buffer
 * Returns start append position in WAL buffer
 * Must be called while holding the wal lock
 * to avoid concurrency issues
 */
static inline uint64_t aura_db_wal_buf_reserve(struct aura_db_wal *wal, size_t len) {
    uint64_t off = wal->buf_off;
    wal->buf_off += len;
    return off;
}

/**
 * Append the staged transaction data to WAL buffer.
 * This function does not touch the stored data that
 * is private to the buffer.
 * Returns the insert offset of the record
 */
static off_t a_db_log_buf_append(AURA_DB *db, struct aura_db_tx *tx) {
    uint64_t buf_len; /* available cache len */
    uint64_t bytes_to_write, written, chunk, off;
    off_t rec_lsn;
    const uint8_t *src;
    bool did_reserve = false;
    struct aura_db_wal *wal = &db->wal;

    /* Try and reserve log buffer space */
    pthread_mutex_lock(&wal->lock);
    rec_lsn = wal->write_lsn;

    /* Update the lsn */
    last_important_lsn = rec_lsn;

    wal->write_lsn += tx->rec_len;
    buf_len = A_WAL_BUF_SZ - wal->buf_off;

    if (buf_len >= tx->rec_len) {
        tx->reserved_off = aura_db_wal_buf_reserve(wal, tx->rec_len);
        did_reserve = true;
        wal->holding_flush++;
    }
    pthread_mutex_unlock(&wal->lock);

    if (did_reserve) {
        /**
         * Reserved wal buffer space should correctly
         * accomodate all WAL fragments
         */
        for (int i = 0; i < tx->rdata_cnt; ++i) {
            bytes_to_write = tx->rdata[i].len;
            src = tx->rdata[i].data;

            memcpy(wal->cache_buf + tx->reserved_off, src, bytes_to_write);
            tx->reserved_off += bytes_to_write;
        }

        /**
         * Permit flush to execute, and wake
         * up anybody waiting to flush the buffer
         */
        pthread_mutex_lock(&wal->lock);
        wal->holding_flush--;
        pthread_cond_signal(&wal->cond);
        pthread_mutex_unlock(&wal->lock);
    } else {
        int rv = 0;

        /**
         * Long path, hold the WAL lock, append
         * to WAL buffer and flush, since we are flushing,
         * wait for all thread to write their reserved spaces
         * so we don't get a possible data corruption
         */
        pthread_mutex_lock(&wal->lock);
        while (wal->holding_flush > 0)
            pthread_cond_wait(&wal->cond, &wal->lock);

        for (int i = 0; i < tx->rdata_cnt; ++i) {
            bytes_to_write = tx->rdata[i].len;
            src = tx->rdata[i].data;
            written = 0;

            while (written < bytes_to_write) {
                buf_len = A_WAL_BUF_SZ - wal->buf_off;
                if (buf_len == 0) {
                    rv = a_db_log_flush(wal, A_DB_LOG_WRITER_FORCE);
                    if (rv < 0)
                        return -1;

                    continue;
                }

                chunk = a_min(bytes_to_write, buf_len);
                memcpy(wal->cache_buf + wal->buf_off, src + written, chunk);
                wal->buf_off += chunk;
                written += chunk;
            }
        }
        pthread_mutex_unlock(&wal->lock);

        /* Request checkpoint if buffer size is adequate */
        if (rv == 1) {
            pthread_mutex_lock(&db->checkpoint_ctx.lock);
            ++db->checkpoint_ctx.nr_of_reqs;
            db->checkpoint_ctx.flags |= A_DB_CHECKPOINT_LOG;
            pthread_mutex_unlock(&db->checkpoint_ctx.lock);
            pthread_cond_signal(&db->checkpoint_ctx.cond);
        }
    }

    /**
     * ASYNC mode return immediately and
     * do not wait for record to make it to
     * disk
     */
    if (tx->flags & A_DB_TX_FL_ASYNC)
        return rec_lsn;

    /* Wait for record to be flushed to disk */
    pthread_mutex_lock(&wal->lock);
    while (glob_flushed_lsn < rec_lsn)
        pthread_cond_wait(&wal->cond, &wal->lock);
    pthread_mutex_unlock(&wal->lock);

    return rec_lsn;
}

static int a_db_tx_stage_data(struct aura_db_tx *tx, const void *data_ptr, uint32_t len) {
    struct aura_db_rdata *slot;

    if (tx->rdata_cnt > A_DB_MAX_TX_REC_CNT) {
        /* Too many WAL rec fragments */
        return -1;
    }

    slot = &tx->rdata[tx->rdata_cnt++];
    slot->data = data_ptr;
    slot->len = len;

    return 0;
}

/**
 * stage record data in transaction context
 */
static inline int a_db_stage_rec(struct aura_db_tx *tx, struct aura_db_wal_rec_hdr *wal_hdr,
                                 struct aura_db_rec_hdr *rec_hdr, struct aura_iovec *key,
                                 struct aura_iovec *data) {
    if (a_db_tx_stage_data(tx, (void *)wal_hdr, sizeof(*wal_hdr)) < 0)
        return -1;

    if (a_db_tx_stage_data(tx, (void *)rec_hdr, sizeof(*rec_hdr)) < 0)
        return -1;

    if (a_db_tx_stage_data(tx, (void *)key->base, key->len) < 0)
        return -1;

    /* Records can lack the data when it's a delete record */
    if (data && a_db_tx_stage_data(tx, (void *)data->base, data->len) < 0)
        return -1;

    return 0;
}

/**
 * Spill data stored in private tx buffers into the WAL buffer.
 * This function does not touch the staged data at all, and
 * only works with private stored record data
 */
static int a_db_tx_spill_to_wal_buf(struct aura_db_wal *wal, struct aura_db_tx *tx) {
    uint64_t wbuf_len; /* available cache len */
    uint64_t bytes_to_write, written, chunk, off;
    // struct aura_sliding_buf *buf;
    const uint8_t *src;
    bool did_reserve = false;
    int rv = 0;

    // A_BUG_ON_2(aura_list_is_empty(&tx->buf_list), true);
    A_BUG_ON_2(aura_sliding_buf_is_empty(&tx->priv_buf), true);

    /* Try and reserve wal buffer space */
    pthread_mutex_lock(&wal->lock);
    /* Update the lsn */
    wal->write_lsn += tx->rec_len;
    wbuf_len = A_WAL_BUF_SZ - wal->buf_off;
    if (wbuf_len >= tx->rec_len) {
        tx->reserved_off = aura_db_wal_buf_reserve(wal, tx->rec_len);
        did_reserve = true;
        wal->holding_flush++;
    }
    pthread_mutex_unlock(&wal->lock);

    if (did_reserve) {
        // a_list_for_each(buf, &tx->buf_list, allocated.link) {
        bytes_to_write = aura_sliding_buf_read_len(&tx->priv_buf);
        src = aura_sliding_buf_read_ptr(&tx->priv_buf);

        /**
         * Copy to WAL buffer starting at the reserved byte (tx->start_off)
         */
        memcpy(wal->cache_buf + tx->reserved_off, src, bytes_to_write);
        //     tx->reserved_off += bytes_to_write;
        // }

        /**
         * Permit flush to execute, and wake
         * up anybody waiting to flush the buffer
         */
        pthread_mutex_lock(&wal->lock);
        --(wal->holding_flush);
        pthread_cond_signal(&wal->cond);
        pthread_mutex_unlock(&wal->lock);
    } else {
        /**
         * Long path, hold the WAL lock, append
         * to WAL buffer and flush, since we are flushing,
         * wait for all thread to write their reserved spaces
         * so we don't get a possible data corruption
         */
        pthread_mutex_lock(&wal->lock);
        while (wal->holding_flush > 0)
            pthread_cond_wait(&wal->cond, &wal->lock);

        // a_list_for_each(buf, &tx->buf_list, allocated.link) {
        bytes_to_write = aura_sliding_buf_read_len(&tx->priv_buf);
        src = aura_sliding_buf_read_ptr(&tx->priv_buf);
        written = 0;

        while (written < bytes_to_write) {
            wbuf_len = A_WAL_BUF_SZ - wal->buf_off;
            if (wbuf_len == 0) {
                rv = a_db_log_flush(wal, A_DB_LOG_WRITER_FORCE);
                if (rv < 0) {
                    break;
                }
                continue;
            }

            chunk = a_min(bytes_to_write, wbuf_len);
            memcpy(wal->cache_buf + wal->buf_off, src + written, chunk);
            wal->buf_off += chunk;
            written += chunk;
        }
        // }

        pthread_mutex_unlock(&wal->lock);
    }

    /* Remove private data flag */
    tx->flags &= ~A_DB_TX_FL_PRIV_DATA;
    /* let thread data reset cleanup the private buffers */

    return rv;
}

static void a_db_init_tx(AURA_DB *db, struct aura_db_th_data *th_data,
                         int tx_kind, uint64_t timeout, int flags) {
    struct aura_db_tx *tx = &th_data->tx;

    th_data->glob_tx_idx = -1;
    tx->id = A_DB_NIL_TX_ID;
    tx->kind = tx_kind;
    tx->ttl = timeout;
    tx->flags = flags | A_DB_TX_FL_VIRT;
    tx->max_priv_data_sz = A_DB_TX_PRIVATE_DATA_SZ;

    // aura_list_head_init(&tx->buf_list);
    tx->timestamp = aura_now_ms(CLOCK_MONOTONIC);
}

/**
 * Begin multi record transcation
 */
int aura_db_transaction_begin(AURA_DBHANDLE _db, int tx_type, uint64_t timeout) {
    AURA_DB *db = _db;
    struct aura_db_th_data *th_data = pthread_getspecific(thread_key);
    /**
     * First invocation, create the thread data
     */
    if (!th_data) {
        th_data = calloc(1, sizeof(*th_data));
        if (!th_data)
            return -1;
    } else {
        A_BUG_ON_2(th_data->glob_tx_idx != -1, true);
        A_BUG_ON_2(th_data->tx.flags != A_DB_TX_FL_NIL, true);
        A_BUG_ON_2(th_data->tx.state != A_DB_TX_NIL, true);
    }

    int flags = A_DB_TX_FL_MR | A_DB_TX_FL_SYNC | A_DB_TX_FL_PRIV_DATA;
    a_db_init_tx(db, th_data, tx_type, timeout, flags);

    pthread_setspecific(thread_key, (void *)th_data);

    return 0;
}

int aura_db_transaction_commit(AURA_DBHANDLE _db) {
    struct aura_db_th_data *th_data;
    struct aura_db_tx *tx;
    struct aura_db_commit rec;
    struct aura_db_rec_hdr rec_hdr;
    struct aura_db_wal_rec_hdr wal_rec_hdr;
    AURA_DB *db = _db;
    bool has_private_data = false;
    char commit_key[64];

    th_data = pthread_getspecific(thread_key);
    A_BUG_ON_2(!th_data, true);

    tx = &th_data->tx;
    memset(commit_key, 0, sizeof(commit_key));
    snprintf(commit_key, sizeof(commit_key), "tx:%ld", tx->id);

    rec.rec_cnt = tx->rec_cnt;
    rec.tx_id = tx->id;
    rec.state = A_DB_TX_COMMITTED;

    struct aura_iovec c_key = {
      .base = commit_key,
      .len = strlen(commit_key),
    };

    struct aura_iovec c_data = {
      .base = (char *)&rec,
      .len = sizeof(rec),
    };

    if (a_db_rec_hdr_init(
          db,
          &rec_hdr,
          A_DB_TX_NS,
          A_DB_COMMIT_SCHEMA_ID,
          A_DB_NIL_TX_ID,
          A_DB_NIL_PREV_TX_REC_OFF,
          &c_key,
          &c_data,
          A_DB_NIL_FLAGS) < 0) {
        goto err;
    }

    a_db_wal_rec_hdr_init(&wal_rec_hdr, A_DB_LOG_TYPE_COMMIT, &rec_hdr, tx->op);

    /**
     * Stage commit record
     */
    if (a_db_stage_rec(tx, &wal_rec_hdr, &rec_hdr, &c_key, &c_data) < 0)
        goto err;

    /**
     * If data was stored in private tx buffer, we must append
     * it to the WAL before handling adding the commit record.
     * If data was not stored in private buffer, then the commit
     * rec is the last rec of the transaction we will handle.
     * We store the private data state because spilling to wal
     * removes the flag.
     */
    has_private_data = tx->flags & A_DB_TX_FL_PRIV_DATA;
    if (has_private_data) {
        if (a_db_tx_spill_to_wal_buf(&db->wal, tx) < 0)
            goto err;
    }

    if (a_db_log_buf_append(db, tx) < 0)
        goto err;

    /**
     * For privately stored data, we can merge the
     * scattered data into one continuous block, and be
     * able to add it to the write cache in exact order
     */
    if (has_private_data) {
        struct aura_sliding_buf *buf;
        struct aura_db_wal_rec_hdr *wal_hdr;
        struct aura_db_rec_hdr *rec_hdr;
        uint64_t buf_len, read_len;
        uint8_t *src;
        // struct aura_iovec tx_data;

        /** @todo: */
        if (tx->rec_len > A_DB_CACHE_SIZE) {
            /* force checkpoint */
            return 0;
        }

        /**
         * Merge scattered data into one block
         */
        // tx_data.base = aura_alloc(db->mc, tx->rec_len);
        // if (!tx_data.base)
        //     goto err;
        // tx_data.len = 0;

        // while (!aura_list_is_empty(&tx->buf_list)) {
        //     a_list_dequeue(buf, &tx->buf_list, allocated.link);

        //     buf_len = aura_sliding_buf_read_len(buf);
        //     src = aura_sliding_buf_read_ptr(buf);

        //     memcpy(tx_data.base + tx_data.len, src, buf_len);
        //     tx_data.len += buf_len;
        // }

        /**
         * For each tx log record, append to write cache
         */
        struct aura_iovec key, data;
        read_len = 0;
        buf_len = aura_sliding_buf_read_len(&tx->priv_buf);
        src = aura_sliding_buf_read_ptr(&tx->priv_buf);

        // while (read_len < tx_data.len) {
        while (read_len < buf_len) {
            // wal_hdr = (struct aura_db_wal_rec_hdr *)(tx_data.base);
            // rec_hdr = (struct aura_db_rec_hdr *)(tx_data.base + sizeof(*wal_hdr));
            wal_hdr = (struct aura_db_wal_rec_hdr *)(src);
            rec_hdr = (struct aura_db_rec_hdr *)(src + sizeof(*wal_hdr));

            // key.base = tx_data.base + sizeof(*wal_hdr) + sizeof(*rec_hdr);
            key.base = src + sizeof(*wal_hdr) + sizeof(*rec_hdr);
            key.len = rec_hdr->key_len;
            data.base = key.base + key.len;
            data.len = rec_hdr->data_len;

            /* skip tx related records */
            if (rec_hdr->ns != A_DB_TX_NS)

                if (a_db_write_cache_append(db, rec_hdr, &key, &data) < 0) {
                    // aura_free(tx_data.base);
                    goto err;
                }

            read_len += wal_hdr->rec_len;
            // tx_data.base += wal_hdr->rec_len;
            src += wal_hdr->rec_len;
        }
    } else {
        /* checkpoint as record already spilled into WAL */
    }

    a_db_reset_th_data(th_data);
    pthread_setspecific(thread_key, (void *)th_data);
    return 0;

err:
    a_db_reset_th_data(th_data);
    pthread_setspecific(thread_key, (void *)th_data);
    return -1;
}

static inline int a_db_transaction_abort(AURA_DB *db, struct aura_db_tx *tx) {
    struct aura_db_commit commit_rec;
    struct aura_db_rec_hdr rec_hdr;
    struct aura_db_wal_rec_hdr log_hdr;
    char commit_key[64];
    int rv;

    /* Transactions */
    if (tx->flags & A_DB_TX_FL_MR) {
        /**
         * If data was already spilled to the WAL,
         * then we need to insert the abort record
         */
        if ((tx->flags & A_DB_TX_FL_PRIV_DATA) == 0) {
            commit_rec.state = A_DB_TX_ABORTED;
            commit_rec.tx_id = tx->id;
            commit_rec.rec_cnt = 0;

            struct aura_iovec c_key = {
              .base = commit_key,
              .len = strlen(commit_key),
            };

            struct aura_iovec c_data = {
              .base = (char *)&commit_rec,
              .len = sizeof(commit_rec),
            };

            rv = a_db_rec_hdr_init(
              db,
              &rec_hdr,
              A_DB_TX_NS,
              A_DB_COMMIT_SCHEMA_ID,
              A_DB_NIL_TX_ID,
              A_DB_NIL_PREV_TX_REC_OFF,
              &c_key,
              &c_data,
              A_DB_NIL_FLAGS);
            if (rv < 0)
                return -1;

            a_db_wal_rec_hdr_init(&log_hdr, A_DB_LOG_TYPE_COMMIT, &rec_hdr, tx->op);

            /**
             * Stage commit record
             */
            rv = a_db_stage_rec(tx, &log_hdr, &rec_hdr, &c_key, &c_data);
            if (rv < 0)
                return -1;

            rv = a_db_log_buf_append(db, tx);
            if (rv < 0)
                return -1;
        }
    }

    return 0;
}

int aura_db_transaction_cancel(AURA_DBHANDLE _db) {
    AURA_DB *db = _db;
    struct aura_db_th_data *th_data;
    struct aura_db_commit commit_rec;
    struct aura_db_rec_hdr rec_hdr;
    struct aura_db_wal_rec_hdr log_hdr;
    struct aura_db_tx *tx;
    char commit_key[64];
    int rv;

    th_data = pthread_getspecific(thread_key);
    A_BUG_ON_2(!th_data, true);

    rv = a_db_transaction_abort(db, &th_data->tx);
out:
    a_db_reset_th_data(th_data);
    pthread_setspecific(thread_key, (void *)th_data);
    return rv;
}

static inline bool a_db_trigger_checkpointer(struct aura_db_wal *wal) {
    if ((last_important_lsn - last_checkpoint_lsn) > A_DB_LOG_SZ_THRESHOLD)
        return true;

    return false;
}

static inline bool a_db_log_should_write(struct aura_db_wal *wal, int flags) {
    if (wal->write_lsn <= glob_flushed_lsn)
        return false;

    return true;
}

/**
 * Flush WAL buffer to WAL log file
 * WAL lock must be held when flushing
 * When 1 is returned, it indicates we can
 * request a checkpoint with LOG as the cause
 */
static inline int a_db_log_flush(struct aura_db_wal *wal, int flags) {
    struct aura_db_wal_rec_hdr *wal_rec;
    uint64_t lsn, written, to_write;
    ssize_t w_len;
    int rv = 0;

    if (!a_db_log_should_write(wal, flags))
        return rv;

    to_write = wal->buf_off;
    written = 0;

    do {
        to_write -= written;
        w_len = write(wal->fd, wal->cache_buf, to_write);
        written += w_len;
    } while (written != to_write && (errno == EAGAIN || errno == EWOULDBLOCK));

    if (written != wal->buf_off)
        return -1;

    fdatasync(wal->fd);

    /**
     * Reset wal buffer
     */
    wal->buf_off = 0;

    /**
     * Since this function is called when the WAL lock
     * is held, the global flushed lsn can be updated
     * safely and SYNC threads alerted
     */
    glob_flushed_lsn = wal->write_lsn;
    if (a_db_trigger_checkpointer(wal))
        rv = 1;

    /* Any thread waiting for wal buffer can resume */
    pthread_cond_broadcast(&wal->cond);

    return rv;
}

/**
 * Release an active slot held by this transaction
 * and notify a thread waiting for get slot
 */
static inline void a_db_release_active_tx(struct aura_db_tx_ctx *tx, uint32_t idx) {
    pthread_mutex_lock(&tx->lock);
    aura_bitmap_clear_bit(idx, tx->tx_tab_map);
    tx->tx_tab[idx].abort = false;
    tx->tx_tab[idx].id = 0;
    tx->tx_tab[idx].state = A_DB_TX_NIL;
    pthread_mutex_unlock(&tx->lock);
    pthread_cond_signal(&tx->wait);
}

static int a_db_tx_priv_buf_append(struct aura_db_tx *tx, struct aura_mem_ctx *mc, uint64_t curr_len) {
    // struct aura_sliding_buf *last_buf, *buf;
    uint64_t off, data_len, buf_len, chunk, pad_len, total_len;
    const uint8_t *src;

    /* Update transaction record len */
    tx->rec_len += curr_len;
    tx->rec_cnt++;

    /* Total len minus padding */
    total_len = 0;

    /**
     * Since we lazily create the first private tx buffer.
     * We must check for it's existence here.
     */
    // if (aura_list_is_empty(&tx->buf_list)) {
    //     buf = aura_sliding_buf_create(mc, A_DB_TX_BUF_SZ, A_SLIDING_BUF_FL_FIXED);
    //     if (!buf)
    //         return -1;

    //     aura_list_add_tail(&tx->buf_list, &buf->allocated.link);
    //     last_buf = buf;
    // } else {
    //     last_buf = a_list_last_entry(&tx->buf_list, struct aura_sliding_buf, allocated.link);
    // }
    if (!aura_sliding_buf_is_initialized(&tx->priv_buf)) {
        if (aura_sliding_buf_init(&tx->priv_buf, mc, A_DB_TX_BUF_SZ, A_SLIDING_BUF_FL_NONE) < 0)
            return -1;
    }

    for (int i = 0; i < tx->rdata_cnt; ++i) {
        data_len = tx->rdata[i].len;
        total_len += data_len;
        src = tx->rdata[i].data;
        // off = 0;

        // while (data_len > 0) {
        //     buf_len = aura_sliding_buf_write_len(last_buf);
        //     if (buf_len == 0) {
        //         buf = aura_sliding_buf_create(mc, A_DB_TX_BUF_SZ, A_SLIDING_BUF_FL_FIXED);
        //         if (!buf)
        //             return -1;

        //         aura_list_add_tail(&tx->buf_list, &buf->allocated.link);
        //         last_buf = buf;
        //         buf_len = aura_sliding_buf_write_len(last_buf);
        //     }

        //     chunk = a_min(data_len, buf_len);
        //     aura_sliding_buf_append(last_buf, src + off, chunk);
        //     off += chunk;
        //     data_len -= chunk;
        // }
        if (aura_sliding_buf_append(&tx->priv_buf, src, data_len) < 0)
            return -1;
    }

    /**
     * Because we align the record up to some alignment,
     * but the rdata len is exact len per record. We can
     * having padding at the end of ,
     * which we take into account as seen below
     */
    pad_len = curr_len - total_len;
    if (pad_len > 0) {
        char pad[pad_len];
        memset(pad, 0, pad_len);
        off = 0;

        if (aura_sliding_buf_append(&tx->priv_buf, pad, pad_len) < 0)
            return -1;

        // while (pad_len > 0) {
        //     buf_len = aura_sliding_buf_write_len(last_buf);
        //     if (buf_len == 0) {
        //         buf = aura_sliding_buf_create(mc, A_DB_TX_BUF_SZ, A_SLIDING_BUF_FL_FIXED);
        //         if (!buf)
        //             return -1;

        //         aura_list_add_tail(&tx->buf_list, &buf->allocated.link);
        //         last_buf = buf;
        //         buf_len = aura_sliding_buf_write_len(last_buf);
        //     }

        //     chunk = a_min(pad_len, buf_len);
        //     aura_sliding_buf_append(last_buf, pad + off, chunk);
        //     off += chunk;
        //     pad_len -= chunk;
        // }
    }

    /**
     * Reset the rdata count since the data is
     * already in the private buffer safely
     */
    tx->rdata_cnt = 0;

    return 0;
}

static inline bool a_db_write_cache_should_flush(struct aura_db_cache_buf *buf, int flags) {
    if (buf->size == 0)
        return false;

    if (flags & A_DB_WRITE_CACHE_FLUSH_FORCE)
        return true;

    if (buf->size <= A_DB_WRITE_CACHE_LOW_BUF_THRESHOLD(buf->cap))
        return false;

    return true;
}

/**
 * Swap write cache active buffer
 * cache lock must be held before
 * calling the function.d
 */
static void a_db_write_cache_swap_active_buf(struct aura_db_write_cache *cache) {
    struct aura_db_cache_buf *inactive_buf, *to_flush_buf;
    int active_idx, inactive_idx;

    to_flush_buf = &cache->bufs[active_idx];
    inactive_idx = 1 - cache->active_idx;
    inactive_buf = &cache->bufs[inactive_idx];

    /**
     * The case where both buffers are filled up.
     * Just block and wait for the free buffer to be released
     */
    while (inactive_buf->flags & A_DB_WRITE_CACHE_SYNCING) {
        pthread_cond_wait(&cache->sync_cond, &cache->lock);
    }

    /* Prepare the new buffer for write */
    a_db_reset_cache_buf(inactive_buf);
    cache->active_idx = inactive_idx;
    cache->next_off = 0;
    to_flush_buf->flags |= A_DB_WRITE_CACHE_SYNCING;
}

/**
 *
 */
static int a_db_write_cache_append(AURA_DB *db, struct aura_db_rec_hdr *rec_hdr,
                                   struct aura_iovec *key, struct aura_iovec *data) {
    struct aura_db_cache_buf *active_buf;
    struct aura_db_write_cache *cache = &db->cache.wrt_cache;
    uint64_t next_append_off;
    uint64_t prev_rec_cache_off;
    bool should_flush = false;
    int rv;

    if (rec_hdr->rec_len.aligned_len > A_DB_CACHE_SIZE) {
        /** @todo: avoid this case */
        return 0;
    }

    pthread_mutex_lock(&cache->lock);

    while (true) {
        active_buf = &cache->bufs[cache->active_idx];

        /**
         * Because the hash bucket chain is updated on
         * checkpoint, this records previous off in the chain
         * is correctly updated before adding it to the
         * permanent DB. Since we always read the correct prev off
         * from file, we can use the cache records cache offset to
         * create a correct cache chain as this will not touch the real
         * file prev off associated with this record.
         */
        prev_rec_cache_off = active_buf->hash_bucket[rec_hdr->hash].head_off;
        next_append_off = active_buf->size + rec_hdr->rec_len.aligned_len;

        /* Current record can fit in cache */
        if (next_append_off <= active_buf->cap) {
            char *write_ptr = active_buf->data + active_buf->size;
            memcpy(write_ptr, rec_hdr, sizeof(*rec_hdr));

            /* key offset */
            write_ptr += sizeof(*rec_hdr);
            memcpy(write_ptr, key->base, rec_hdr->key_len);

            if (data) {
                /* data offset */
                write_ptr += rec_hdr->key_len;
                memcpy(write_ptr, data->base, data->len);
            }

            rec_hdr->prev_cache_off = prev_rec_cache_off;
            active_buf->hash_bucket[rec_hdr->hash].head_off = cache->next_off;
            cache->next_off += rec_hdr->rec_len.aligned_len;

            active_buf->flags |= A_DB_WRITE_CACHE_DIRTY;
            active_buf->size += rec_hdr->rec_len.aligned_len;

            /* Trigger flush if threshold permits it */
            if (a_db_write_cache_should_flush(active_buf, 0))
                should_flush = true;

            pthread_mutex_unlock(&cache->lock);

            /* Trigger flush if threshold permits it */
            if (should_flush) {
                pthread_mutex_lock(&db->bgwriter.lock);
                db->bgwriter.do_work = true;
                pthread_cond_signal(&db->bgwriter.cond);
                pthread_mutex_unlock(&db->bgwriter.lock);
            }

            return 0;
        }

        /* swap active buffer */
        a_db_write_cache_swap_active_buf(cache);

        /* Trigger buffer flush */
        pthread_mutex_unlock(&cache->lock);

        /* Acquire bg writer lock and trigger bg writer */
        pthread_mutex_lock(&db->bgwriter.lock);
        db->bgwriter.do_work = true;
        pthread_cond_signal(&db->bgwriter.cond);
        pthread_mutex_unlock(&db->bgwriter.lock);

        /* Reacquire the write buf_cache and try again */
        pthread_mutex_lock(&cache->lock);
    }

    return rv;
}

static int _a_db_rec_insert(AURA_DB *db, struct aura_db_th_data *th_data, ns_t namespace,
                            schema_id_t schema_id, uint16_t flags, aura_db_log_rec_type log_type,
                            aura_db_op op, struct aura_iovec *key, struct aura_iovec *data) {
    struct aura_db_tx *tx;
    struct aura_db_rec_hdr rec_hdr, commit_rec_hdr;
    struct aura_db_wal_rec_hdr wal_rec_hdr, commit_rec_wal_hdr;
    struct aura_db_commit commit_rec;
    int rv;

    tx = &th_data->tx;
    rv = a_db_can_accept_req(db, tx->id, th_data->glob_tx_idx);

    /* Abort transaction */
    if (rv == A_DB_REQ_ABORT) {
        rv = a_db_transaction_abort(db, tx);
        a_db_release_active_tx(&db->tx_ctx, th_data->glob_tx_idx);
        a_db_reset_th_data(th_data);
        return rv;
    } else if (rv == A_DB_REQ_REJECTED)
        return -1;

    if (tx->flags & A_DB_TX_FL_VIRT)
        a_db_tx_promote(db, th_data);

    /* construct wal record */
    if (a_db_rec_hdr_init(
          db,
          &rec_hdr,
          namespace,
          schema_id,
          tx->id,
          A_DB_NIL_PREV_TX_REC_OFF,
          key,
          data,
          flags) < 0) {
        return -1;
    }

    a_db_wal_rec_hdr_init(&wal_rec_hdr, log_type, &rec_hdr, op);

    /**
     * stage WAL record
     */
    if (a_db_stage_rec(tx, &wal_rec_hdr, &rec_hdr, key, data) < 0)
        return -1;

    if (tx->flags & A_DB_TX_FL_MR) {
        /**
         * Accumulate data in tx private buffer when still
         * under the threshold size for private tx data
         */
        if (tx->flags & A_DB_TX_FL_PRIV_DATA) {
            if ((tx->rec_len + wal_rec_hdr.rec_len) < tx->max_priv_data_sz) {
                if (a_db_tx_priv_buf_append(tx, db->mc, wal_rec_hdr.rec_len) < 0) {
                    /* abandon transaction */
                    return -1;
                }
            } else {
                /**
                 * private tx data has reached it maximum before
                 * final commit, we spill into WAL buf and switch
                 * to pushing directly into WAL buf.
                 */
                if (a_db_tx_spill_to_wal_buf(&db->wal, tx) < 0)
                    return 1;

                /**
                 * Adjust the tx len to reflect new correct rec length
                 */
                tx->rec_len = wal_rec_hdr.rec_len;
                if (a_db_log_buf_append(db, tx) < 0)
                    return -1;
            }
        } else {
            tx->rec_len = wal_rec_hdr.rec_len;
            if (a_db_log_buf_append(db, tx) < 0)
                return -1;
        }
    } else {
        /**
         * For single record, we do the shortcut
         * and stage WAL commit record
         */
        char commit_key[64];
        memset(commit_key, 0, sizeof(commit_key));
        snprintf(commit_key, sizeof(commit_key), "tx:%ld", tx->id);

        commit_rec.rec_cnt = 1;
        commit_rec.tx_id = tx->id;
        commit_rec.state = A_DB_TX_COMMITTED;

        struct aura_iovec c_key = {
          .base = commit_key,
          .len = strlen(commit_key),
        };

        struct aura_iovec c_data = {
          .base = (char *)&commit_rec,
          .len = sizeof(commit_rec),
        };

        if (a_db_rec_hdr_init(
              db,
              &commit_rec_hdr,
              A_DB_TX_NS,
              A_DB_COMMIT_SCHEMA_ID,
              A_DB_NIL_TX_ID,
              A_DB_NIL_PREV_TX_REC_OFF,
              &c_key,
              &c_data,
              A_DB_NIL_FLAGS) < 0) {
            return -1;
        }

        a_db_wal_rec_hdr_init(&commit_rec_wal_hdr, A_DB_LOG_TYPE_COMMIT, &rec_hdr, op);

        /**
         * Stage commit record
         */
        if (a_db_stage_rec(tx, &commit_rec_wal_hdr, &commit_rec_hdr, &c_key, &c_data) < 0)
            return -1;

        tx->rec_len = wal_rec_hdr.rec_len + commit_rec_wal_hdr.rec_len;

        /* Append to WAL buffer */
        if (a_db_log_buf_append(db, tx) < 0)
            return -1;

        /* Append to data write cache */
        if (a_db_write_cache_append(db, &rec_hdr, key, data) < 0) {
            return -1;
        }

        /**
         * In the case of no error
         * Clear the active tx slot and reset thread specific data here
         * since the caller only takes care of clearing these
         * resources in the case of an error
         */
        a_db_release_active_tx(&db->tx_ctx, th_data->glob_tx_idx);
        a_db_reset_th_data(th_data);
    }

    return 0;
}

int aura_db_insert(AURA_DBHANDLE _db, ns_t namespace, schema_id_t schema_id,
                   uint16_t flags, aura_db_op op, struct aura_iovec *key,
                   struct aura_iovec *data) {
    struct aura_db_th_data *th_data;
    AURA_DB *db = _db;
    int rv;

    th_data = pthread_getspecific(thread_key);

    /**
     * Single record not part of tx
     * Handle implicit tx, skip the long
     * way of using tx buffer and append
     * directly into WAL buffer
     */
    if (!th_data || th_data->tx.state == A_DB_TX_NIL) {
        if (!th_data) {
            th_data = calloc(1, sizeof(*th_data));
            if (!th_data)
                return -1;
            a_db_reset_th_data(th_data);
        }

        int flags = A_DB_TX_FL_SYNC;
        a_db_init_tx(db, th_data, 0, A_DB_TO_INFINITY, flags);
    } else {
        /* Multi record tx */
        A_BUG_ON_2(th_data->tx.state != A_DB_TX_IN_PROGRESS, true);
    }

    rv = _a_db_rec_insert(db, th_data, namespace, schema_id, flags, A_DB_LOG_TYPE_UPDATE, op, key, data);
    if (rv < 0) {
        int r = a_db_transaction_abort(db, &th_data->tx);
        a_db_release_active_tx(&db->tx_ctx, th_data->glob_tx_idx);
        a_db_reset_th_data(th_data);
    }

    pthread_setspecific(thread_key, (void *)th_data);
    return rv;
}

static inline struct aura_db_rec_hdr *_a_db_read_cache_fetch(struct aura_db_read_cache *cache, ns_t namespace,
                                                             schema_id_t schema_id, struct aura_iovec *key,
                                                             uint32_t hash) {
    struct aura_db_rec_hdr *rec_hdr;
    const char *key_buf;
    uint64_t off;

    off = cache->buf.hash_bucket[hash].head_off;
    while (off != UINT64_MAX) {
        /* get record header offset */
        rec_hdr = (struct aura_db_rec_hdr *)(cache->buf.data + off);

        if (rec_hdr->magic != A_DB_REC_MAGIC)
            break;

        if (rec_hdr->ns == namespace &&
            rec_hdr->schema_id == schema_id &&
            rec_hdr->key_len == key->len &&
            rec_hdr->hash == hash) {
            key_buf = (char *)rec_hdr + sizeof(*rec_hdr);
            if (aura_mem_is_eq(key_buf, rec_hdr->key_len, key->base, key->len)) {
                if (rec_hdr->flags & A_DB_FLAG_REC_TOMBSTONE)
                    return NULL;

                return rec_hdr;
            }
        }

        off = rec_hdr->prev_cache_off;
    }

    return NULL;
}

/**
 * Fetch a record from read cache.
 * Cache read lock must be held before
 * calling this function.
 */
static int a_db_read_cache_fetch(AURA_DB *db, ns_t namespace, schema_id_t schema_id,
                                 struct aura_iovec *key, uint32_t hash,
                                 struct aura_db_rec *data_out) {
    struct aura_db_read_cache *rd_cache = &db->cache.read_cache;
    struct aura_db_rec_hdr *rec_hdr;

    pthread_rwlock_rdlock(&rd_cache->rwlock);
    if (rd_cache->buf.size > 0) {
        rec_hdr = _a_db_read_cache_fetch(rd_cache, namespace, schema_id, key, hash);
        if (rec_hdr) {
            if (rec_hdr->flags & A_DB_FLAG_REC_TOMBSTONE) {
                pthread_rwlock_unlock(&rd_cache->rwlock);
                return A_DB_REC_NOT_FOUND;
            }

            if (data_out) {
                data_out->data.len = rec_hdr->data_len;
                data_out->data.base = aura_alloc(db->mc, data_out->data.len);
                if (!data_out->data.base) {
                    pthread_rwlock_unlock(&rd_cache->rwlock);
                    return -1;
                }

                data_out->rec_meta.timestamp = rec_hdr->timestamp_ms;
                memcpy(data_out->rec_meta.check_sum, rec_hdr->checksum, A_DIGEST_LEN);
                memcpy(data_out->data.base, (char *)rec_hdr + sizeof(*rec_hdr) + rec_hdr->key_len, rec_hdr->data_len);
            }

            pthread_rwlock_unlock(&rd_cache->rwlock);
            return 0;
        }
    }
    pthread_rwlock_unlock(&rd_cache->rwlock);

    return A_DB_REC_NOT_FOUND;
}

static inline struct aura_db_rec_hdr *_a_db_write_cache_fetch(struct aura_db_write_cache *cache, ns_t namespace,
                                                              schema_id_t schema_id, struct aura_iovec *key,
                                                              uint32_t hash) {
    struct aura_db_rec_hdr *rec_hdr;
    struct aura_db_cache_buf *buf;
    const char *key_buf;
    uint64_t off;
    int check_idx;
    bool inactive_buf_checked = false;

    check_idx = cache->active_idx;
redo:
    buf = &cache->bufs[check_idx];
    off = buf->hash_bucket[hash].head_off;
    while (off != UINT64_MAX && buf->size > 0) {
        /* get record header offset */
        rec_hdr = (struct aura_db_rec_hdr *)(buf->data + off);

        if (rec_hdr->magic != A_DB_REC_MAGIC)
            break;

        if (rec_hdr->ns == namespace &&
            rec_hdr->schema_id == schema_id &&
            rec_hdr->key_len == key->len &&
            rec_hdr->hash == hash) {
            key_buf = (char *)rec_hdr + sizeof(*rec_hdr);
            if (aura_mem_is_eq(key_buf, rec_hdr->key_len, key->base, key->len)) {
                if (rec_hdr->flags & A_DB_FLAG_REC_TOMBSTONE)
                    return NULL;

                return rec_hdr;
            }
        }

        off = rec_hdr->prev_cache_off;
    }

    /* If inactive buffer has data and hasn't been cleared yet */
    if (inactive_buf_checked)
        return NULL;

    check_idx = 1 - cache->active_idx;
    inactive_buf_checked = true;
    goto redo;
}

/* Check if transaction for this particular record is active */
static inline bool a_db_tx_active(struct aura_db_tx_tab_ent *txs, txid_t id) {
    for (int i = 0; i < A_DB_MAX_CONC_TX; ++i)
        if (txs[i].id == id && txs[i].state == A_DB_TX_IN_PROGRESS)
            return true;

    return false;
}

/* Check for record visibility */
static inline bool a_db_rec_visible(AURA_DB *db, txid_t tx_id) {
    if (tx_id == A_DB_NIL_TX_ID)
        return true;

    if (a_db_tx_active(db->tx_ctx.tx_tab, tx_id))
        return false;

    return true;
}

/**
 * Fetch a record from write cache.
 * Cache read lock must be held before
 * calling this function.
 */
static int a_db_write_cache_fetch(AURA_DB *db, ns_t namespace, schema_id_t schema_id,
                                  struct aura_iovec *key, uint32_t hash,
                                  struct aura_db_rec *data_out) {
    struct aura_db_write_cache *wrt_cache = &db->cache.wrt_cache;
    struct aura_db_rec_hdr *rec_hdr;

    pthread_mutex_lock(&wrt_cache->lock);
    rec_hdr = _a_db_write_cache_fetch(wrt_cache, namespace, schema_id, key, hash);
    if (rec_hdr) {
        if (a_db_rec_visible(db, rec_hdr->tx_id)) {
            if (rec_hdr->flags & A_DB_FLAG_REC_TOMBSTONE) {
                pthread_mutex_unlock(&wrt_cache->lock);
                return A_DB_REC_NOT_FOUND;
            }

            if (data_out) {
                data_out->data.len = rec_hdr->data_len;
                data_out->data.base = aura_alloc(db->mc, data_out->data.len);
                if (!data_out->data.base) {
                    pthread_mutex_unlock(&wrt_cache->lock);
                    return -1;
                }

                data_out->rec_meta.timestamp = rec_hdr->timestamp_ms;
                memcpy(data_out->rec_meta.check_sum, rec_hdr->checksum, A_DIGEST_LEN);
                memcpy(data_out->data.base, (char *)rec_hdr + sizeof(*rec_hdr) + rec_hdr->key_len, rec_hdr->data_len);
            }

            pthread_mutex_unlock(&wrt_cache->lock);
            return 0;
        }
    }
    pthread_mutex_unlock(&wrt_cache->lock);

    return A_DB_REC_NOT_FOUND;
}

static int a_db_cache_fetch(AURA_DB *db, ns_t namespace, schema_id_t schema_id,
                            struct aura_iovec *key, uint32_t hash,
                            struct aura_db_rec *data_out) {
    struct aura_db_write_cache *wrt_cache = &db->cache.wrt_cache;
    struct aura_db_read_cache *rd_cache = &db->cache.read_cache;
    struct aura_db_rec_hdr *rec_hdr;
    int rv;

    /* Write cache possibly has the latest record version */
    rv = a_db_write_cache_fetch(db, namespace, schema_id, key, hash, data_out);
    if (rv < 0)
        return -1;

    /* Record found */
    if (rv == 0)
        return 0;

    /* Otherwise try read cache */
    return a_db_read_cache_fetch(db, namespace, schema_id, key, hash, data_out);
}

static int a_db_fetch(AURA_DB *db, ns_t namespace, schema_id_t schema_id,
                      struct aura_iovec *key, struct aura_db_rec *data_out) {
    struct aura_db_rec_hdr rec_hdr, *hdr;
    char key_buf[2000];
    uint32_t hash;
    lsn_t offset;
    ssize_t res;

    hash = a_fnv1a_hash(A_DB_HASH_BUCKET_CNT, namespace, key);

    pthread_mutex_lock(&db->ctrl_lock);
    offset = db->control.buckets[hash].head_off;
    pthread_mutex_unlock(&db->ctrl_lock);

    while (offset != UINT64_MAX) {
        if (pread(db->main.fd, &rec_hdr, sizeof(rec_hdr), offset) < 0)
            return -1;

        if (rec_hdr.magic != A_DB_REC_MAGIC)
            break;

        memset(key_buf, 0, sizeof(key_buf));
        if (rec_hdr.ns == namespace && rec_hdr.schema_id == schema_id && rec_hdr.key_len == key->len) {
            if (pread(db->main.fd, key_buf, rec_hdr.key_len, offset + sizeof(rec_hdr)) < 0)
                return -1;

            if (aura_mem_is_eq(key_buf, strlen(key_buf), key->base, key->len)) {
                if (rec_hdr.flags & A_DB_FLAG_REC_TOMBSTONE)
                    return A_DB_REC_NOT_FOUND;

                if (data_out) {
                    data_out->data.len = rec_hdr.data_len;
                    data_out->data.base = aura_alloc(db->mc, data_out->data.len);
                    if (!data_out->data.base) {
                        return -1;
                    }

                    res = pread(db->main.fd, data_out->data.base, rec_hdr.data_len, offset + sizeof(rec_hdr) + rec_hdr.key_len);
                    if (res != rec_hdr.data_len) {
                        aura_free(data_out->data.base);
                        return -1;
                    }

                    data_out->rec_meta.timestamp = rec_hdr.timestamp_ms;
                    memcpy(data_out->rec_meta.check_sum, rec_hdr.checksum, A_DIGEST_LEN);

                    pthread_rwlock_wrlock(&db->cache.read_cache.rwlock);
                    if (a_db_read_cache_insert(&db->cache.read_cache, &rec_hdr, key, &data_out->data) < 0) {
                        pthread_rwlock_unlock(&db->cache.read_cache.rwlock);
                        return -1;
                    }
                    pthread_rwlock_unlock(&db->cache.read_cache.rwlock);
                }

                return 0;
            }
        }

        offset = rec_hdr.prev_off;
    }

    return A_DB_REC_NOT_FOUND;
}

int aura_db_fetch(AURA_DBHANDLE _db, ns_t namespace, schema_id_t schema_id,
                  struct aura_iovec *key, struct aura_db_rec *data_out) {
    struct aura_db_rec_hdr rec_hdr, *hdr;
    uint32_t hash;
    off_t offset;
    ssize_t res;
    char key_buf[2000];
    AURA_DB *db = _db;
    int rv;

    hash = a_fnv1a_hash(A_DB_HASH_BUCKET_CNT, namespace, key);

    if (data_out) {
        memset(data_out, 0, sizeof(*data_out));
    }

    /**
     * Cache
     */
    rv = a_db_cache_fetch(db, namespace, schema_id, key, hash, data_out);
    if (rv < 0) {
        return -1;
    }

    if (rv == 0) {
        /* Record found */
        return 0;
    }

    /**
     * DB
     */
    return a_db_fetch(db, namespace, schema_id, key, data_out);
}

int aura_db_delete(AURA_DBHANDLE _db, ns_t namespace, schema_id_t schema_id, struct aura_iovec *key) {
    AURA_DB *db = _db;
    struct aura_db_th_data *th_data;
    off_t offset;
    int rv;

    th_data = pthread_getspecific(thread_key);

    if (!th_data || th_data->tx.state == A_DB_TX_NIL) {
        if (!th_data) {
            th_data = calloc(1, sizeof(*th_data));
            if (!th_data)
                return -1;
            a_db_reset_th_data(th_data);
        }

        int flags = A_DB_TX_FL_SYNC;
        a_db_init_tx(db, th_data, 0, A_DB_TO_INFINITY, flags);
    } else {
        /* Multi record tx */
        A_BUG_ON_2(th_data->tx.state != A_DB_TX_IN_PROGRESS, true);
    }

    rv = _a_db_rec_insert(
      db,
      th_data,
      namespace,
      schema_id,
      A_DB_FLAG_REC_TOMBSTONE,
      A_DB_LOG_TYPE_UPDATE,
      A_DB_DELETE_OP,
      key,
      NULL);
    if (rv < 0) {
        int r = a_db_transaction_abort(db, &th_data->tx);
        a_db_release_active_tx(&db->tx_ctx, th_data->glob_tx_idx);
        a_db_reset_th_data(th_data);
    }

    pthread_setspecific(thread_key, (void *)th_data);

    return rv;
}

static uint64_t a_db_get_next_tid(AURA_DB *db) {
    uint64_t tx_id;

    pthread_mutex_lock(&db->tx_ctx.lock);
    tx_id = db->tx_ctx.next_id;
    db->tx_ctx.next_id = (db->tx_ctx.next_id + 1) & db->tx_ctx.id_mask;
    pthread_mutex_unlock(&db->tx_ctx.lock);

    return tx_id;
}

static uint64_t a_db_get_oldest_active_tid(AURA_DB *db) {
    uint64_t oldest_active_tx_id, tx_id;

    oldest_active_tx_id = atomic_load(&db->tx_ctx.next_id);

    for (int i = 0; i < A_DB_MAX_CONC_TX; ++i) {
        tx_id = db->tx_ctx.tx_tab[i].id;
        if (tx_id < oldest_active_tx_id)
            oldest_active_tx_id = tx_id;
    }

    return oldest_active_tx_id;
}

/**
 * Flush active write cache to disk.
 * We switch the active cache buffer to point
 * to the "free" buffer.
 */
static int a_db_write_cache_flush(AURA_DB *db, int flags) {
    struct aura_db_write_cache *cache;
    struct aura_db_cache_buf *to_flush;
    struct aura_db_rec_hdr *rec_hdr;
    uint64_t off;

    cache = &db->cache.wrt_cache;

    pthread_mutex_lock(&cache->lock);
    to_flush = &cache->bufs[cache->write_idx];

    if (!a_db_write_cache_should_flush(to_flush, flags)) {
        pthread_mutex_unlock(&cache->lock);
        return 0;
    }

    /**
     * If active index is not equal to write index,
     * active buffer moved one step, as a result of the
     * current inactive buffer being filled up. As such,
     * write index should move to point to the current active
     * buffer. So the next call to flush points to the correct
     * to_flush buffer
     */
    if (cache->active_idx != cache->write_idx)
        cache->write_idx = 1 - cache->write_idx;
    pthread_mutex_unlock(&cache->lock);

    /**
     * Since we want to perform actual write without blocking reads.
     * We snapshot the current db control version
     * We use the control cond var to block any other thread. This prevents
     * corrupting the control info incase a new write-cache flush
     * happens to be invoked in another thread. We would not want this
     * new cache flush to update a stale db control.
     */
    struct aura_db_control control;
    while (true) {
        pthread_mutex_lock(&db->ctrl_lock);
        while (db->ctrl_busy)
            pthread_cond_wait(&db->ctrl_cond, &db->ctrl_lock);

        db->ctrl_busy = true;

        memcpy(&control, &db->control, sizeof(control));
        pthread_mutex_unlock(&db->ctrl_lock);
        break;
    }

    /**
     * Because of keeping records in thread private storage and
     * because I haven't thought hard about how to cohesively
     * update record chains and hash bucket. What we can do for now
     * is loop over the records in the buffer here and update control and
     * record chain.
     * We can also allow cache reads using this same to_flush buffer,
     * because cache reads use the record cache offset which remain
     * unchanged during the duration of the entire buffer write.
     * Also db reads can proceed as we only append, and the current
     * control would not read any newly appended data yet.
     */
    off = 0;
    while (off < to_flush->size) {
        rec_hdr = (struct aura_db_rec_hdr *)(to_flush->data + off);
        A_BUG_ON_2(rec_hdr->magic != 0xED5EC001, true);

        rec_hdr->prev_off = control.buckets[rec_hdr->hash].head_off;
        control.buckets[rec_hdr->hash].head_off = control.file_size;
        control.file_size += rec_hdr->rec_len.aligned_len;
        control.record_cnt++;

        off += rec_hdr->rec_len.aligned_len;
    }

    if (lseek(db->main.fd, 0, SEEK_END) < 0)
        return -1;

    if (write(db->main.fd, to_flush->data, to_flush->size) != to_flush->size)
        return -1;
    fdatasync(db->main.fd);

    /* update control */
    if (lseek(db->ctrl_file_fd, 0, SEEK_SET) < 0)
        return -1;

    if (a_db_meta_write(db->ctrl_file_fd, (void *)&control, sizeof(control)) < 0)
        return -1;
    fdatasync(db->main.fd);

    /* Let threads waiting know we are done with control update */
    pthread_mutex_lock(&db->ctrl_lock);
    db->ctrl_busy = false;
    pthread_cond_signal(&db->ctrl_cond);
    pthread_mutex_unlock(&db->ctrl_lock);

    /* switch control to this new version */
    pthread_mutex_lock(&db->ctrl_lock);
    memcpy(&db->control, &control, sizeof(control));
    pthread_mutex_unlock(&db->ctrl_lock);

    /**
     * Since we hold the cache lock when reading
     * from it. Resetting the cache should work as
     * we would already be done with the cache if we
     * were reading it, or be blocked waiting if we
     * hadn't yet acquired the lock to read from cache.
     * Either way we run before or after this call which
     * means we always have valid data in cache or no
     * data at all.
     */
    pthread_mutex_lock(&cache->lock);
    to_flush->flags &= ~A_DB_WRITE_CACHE_SYNCING;
    pthread_mutex_unlock(&cache->lock);
    /**
     * Alert sync for this buffer is done
     */
    pthread_cond_signal(&cache->sync_cond);

    return 0;
}

static void a_db_checkpoint_th_cleanup(void *arg) {
    AURA_DB *db = arg;

    db->th_pool[A_DB_THREAD_CHECKPOINTER].status = A_DB_BG_TH_STOPPED;
    atomic_fetch_sub(&db->ref_cnt, 1);
}

static inline bool a_db_recovery_in_progress(AURA_DB *db) {
    return (atomic_load(&db->state) == A_DB_STATE_RECOVERY);
}

/**
 * Snapshot the list of active transactions storing
 * the tx ids in tx_ids and returning the active count.
 */
static inline int a_db_get_txs_delaying_chkpt(AURA_DB *db, struct aura_db_tx_tab_ent *txs) {
    int active_cnt = 0;

    pthread_mutex_lock(&db->tx_ctx.lock);
    for (int i = 0; i < A_DB_MAX_CONC_TX; ++i) {
        if (db->tx_ctx.tx_tab[i].state == A_DB_TX_IN_PROGRESS) {
            ++active_cnt;
            memcpy(&txs[i], &db->tx_ctx.tx_tab[i], sizeof(*txs));
        }
    }
    pthread_mutex_unlock(&db->tx_ctx.lock);

    return active_cnt;
}

/**
 * Check active transactions, comparing snapshot against
 * the active tx table
 */
static inline bool a_db_txs_delaying_chkpt(AURA_DB *db, struct aura_db_tx_tab_ent *txs) {
    bool rv = false;

    pthread_mutex_lock(&db->tx_ctx.lock);
    for (int i = 0; i < A_DB_MAX_CONC_TX; ++i) {
        for (int j = 0; j < A_DB_MAX_CONC_TX; ++j) {
            if (db->tx_ctx.tx_tab[i].id == txs[j].id && db->tx_ctx.tx_tab[i].state == A_DB_TX_IN_PROGRESS) {
                rv = true;
                break;
            } else
                txs[j].id = A_DB_NIL_TX_ID;
        }

        if (rv)
            break;
    }
    pthread_mutex_unlock(&db->tx_ctx.lock);

    return rv;
}

static inline bool a_db_checkpoint_should_run(int flags) {
    int flags_no_skip = A_DB_CHECKPOINT_SHUTDOWN | A_DB_CHECKPOINT_RECOVERY | A_DB_CHECKPOINT_FORCE;
    /* No work has been done, abort all together */
    if (last_important_lsn == last_checkpoint_lsn)
        return false;

    /**
     * Checkpoint trigger is timed.
     * If size is too small, ignore trigger.
     */
    if (((last_important_lsn - last_checkpoint_lsn) < A_DB_LOG_SZ_THRESHOLD >> 1) && (flags & flags) == 0)
        return false;

    /**
     * Size large enough or trigger is forced.
     */
    return true;
}

static int a_db_create_checkpoint(AURA_DB *db, struct aura_db_th_data *th_data, int flags) {
    struct aura_db_checkpoint chkpt = {0};
    struct aura_db_rec_hdr rec_hdr;
    struct aura_db_wal_rec_hdr wal_rec_hdr;
    struct aura_db_tx *tx = &th_data->tx;
    off_t rec_off = 0;
    bool shutdown = false;
    int rv, active_xids;

    if (flags & A_DB_CHECKPOINT_SHUTDOWN)
        shutdown = true;

    if (a_db_recovery_in_progress(db) && (flags & A_DB_CHECKPOINT_RECOVERY) == 0) {
        app_debug(true, 0, "Incorrect checkpoint flags at recovery end: flags=%d", flags);
        return -1;
    }

    if (!a_db_checkpoint_should_run(flags)) {
        /**
         * Since shutdown checkpoint runs when all active txs
         * have been finalized. We are guaranteed that no new
         * WAL has been added at the point. See a_db_checkpoint_should_run(),
         * We can simply update control file and shutdown.
         */
        if (shutdown) {
            pthread_mutex_lock(&db->ctrl_lock);
            db->control.shutdown_state = A_DB_STATE_SHUTDOWN;

            if (a_db_meta_write(db->ctrl_file_fd, (void *)&db->control, sizeof(db->control)) < 0) {
                return -1;
            }

            fdatasync(db->ctrl_file_fd);
            pthread_mutex_unlock(&db->ctrl_lock);
        }
        return 0;
    }

    /* Checkpoint taken at */
    aura_now_ts(&chkpt.chkpt_time, CLOCK_MONOTONIC);

    if (shutdown) {
        /**
         * During shutdown, since we wait for all active tx to finalize,
         * no new logs can be added at this point.
         * so wal.write_lsn would point to the end
         * of the file, as also no need to acquire
         * the wal lock to use this
         */
        chkpt.redo_lsn = db->wal.write_lsn;
    } else {
        /**
         * We do not yet know the lsn during
         * online checkpointing, we insert
         * the commit begin record to mark our
         * starting point for next time we run replay
         */
        struct aura_db_checkpoint_begin redo_rec;
        struct aura_iovec key, data;
        char keybuf[64];

        redo_rec.format_version = 1;
        memset(keybuf, 0, sizeof(keybuf));
        snprintf(keybuf, sizeof(keybuf), "%s", A_DB_CHECKPOINT_KEY);
        key.base = keybuf;
        key.len = sizeof(A_DB_CHECKPOINT_KEY) - 1;
        data.base = (char *)&redo_rec;
        data.len = sizeof(redo_rec);

        /* construct wal record */
        if (a_db_rec_hdr_init(
              db,
              &rec_hdr,
              A_DB_TX_NS,
              A_DB_CHECK_PNT_SCHEMA_ID,
              A_DB_NIL_TX_ID,
              A_DB_NIL_PREV_TX_REC_OFF,
              &key,
              &data,
              flags) < 0) {
            return -1;
        }

        a_db_wal_rec_hdr_init(&wal_rec_hdr, A_DB_LOG_TYPE_BEGIN_CKPT, &rec_hdr, A_DB_INSERT_OP);

        if (a_db_stage_rec(tx, &wal_rec_hdr, &rec_hdr, &key, &data) < 0)
            return -1;

        tx->rec_len = wal_rec_hdr.rec_len;
        rec_off = a_db_log_buf_append(db, tx);
        if (rec_off < 0)
            return -1;

        if (a_db_log_flush(&db->wal, A_DB_LOG_WRITER_FORCE) < 0)
            return -1;

        /**
         * redo off becomes the tx begin
         * record, since we can be sure everything
         * before rec_off should be persisted to LOG
         */
        chkpt.redo_lsn = rec_off;
    }

    chkpt.next_txid = a_db_get_next_tid(db);

    /**
     * Wait for sometime transactions delaying checkpoint
     */
    memset(chkpt.trans, 0, sizeof(chkpt.trans));
    active_xids = a_db_get_txs_delaying_chkpt(db, chkpt.trans);
    if (active_xids > 0) {
        uint64_t tx_wait = aura_now_ms(CLOCK_MONOTONIC);
        do {
            sleep(0.01); /* 10ms wait */
            if (aura_now_ms(CLOCK_MONOTONIC) - tx_wait > A_DB_TX_CHECKPOINT_WAIT)
                break;
        } while (a_db_txs_delaying_chkpt(db, chkpt.trans));
    }

    /* Flush cache */
    if (a_db_write_cache_flush(db, A_DB_WRITE_CACHE_FLUSH_FORCE) < 0)
        return -1;

    /* Prepare checkpoint record */
    struct aura_iovec key, data;
    char keybuf[64];

    memset(keybuf, 0, sizeof(keybuf));
    snprintf(keybuf, sizeof(keybuf), "%s", A_DB_CHECKPOINT_KEY);
    key.base = keybuf;
    key.len = sizeof(A_DB_CHECKPOINT_KEY) - 1;
    data.base = (char *)&chkpt;
    data.len = sizeof(chkpt);

    /* construct wal record */
    if (a_db_rec_hdr_init(
          db,
          &rec_hdr,
          A_DB_TX_NS,
          A_DB_CHECK_PNT_SCHEMA_ID,
          A_DB_NIL_TX_ID,
          A_DB_PREV_JOB_REC_NONE,
          &key,
          &data,
          flags) < 0) {
        return -1;
    }

    a_db_wal_rec_hdr_init(&wal_rec_hdr, A_DB_LOG_TYPE_END_CKPT, &rec_hdr, A_DB_INSERT_OP);

    if (a_db_stage_rec(tx, &wal_rec_hdr, &rec_hdr, &key, &data) < 0)
        return -1;

    tx->rec_len = wal_rec_hdr.rec_len;
    rec_off = a_db_log_buf_append(db, tx);
    if (rec_off < 0)
        return -1;

    /* Flush log */
    pthread_mutex_lock(&db->wal.lock);
    while (db->wal.holding_flush > 0)
        pthread_cond_wait(&db->wal.cond, &db->wal.lock);

    if (a_db_log_flush(&db->wal, A_DB_LOG_WRITER_FORCE) < 0) {
        pthread_mutex_unlock(&db->wal.lock);
        return -1;
    }

    pthread_mutex_unlock(&db->wal.lock);

    /* Update control file */
    pthread_mutex_lock(&db->ctrl_lock);
    if (shutdown)
        db->control.shutdown_state = A_DB_STATE_SHUTDOWN;
    db->control.chkpt_copy = chkpt;

    if (a_db_meta_write(db->ctrl_file_fd, (void *)&db->control, sizeof(db->control)) < 0) {
        return -1;
    }

    fdatasync(db->ctrl_file_fd);
    pthread_mutex_unlock(&db->ctrl_lock);

    return rec_off;
}

static void *a_db_checkpointer(void *arg) {
    AURA_DB *db = arg;
    struct aura_db_checkpoint chkpt;
    struct aura_db_th_data *th_data;
    struct timespec ts;
    int64_t now, elapsed;
    bool do_checkpoint, shutdown, timedout = false;
    int rv, flags = 0;
    off_t off;

    th_data = pthread_getspecific(thread_key);
    if (!th_data) {
        th_data = calloc(1, sizeof(*th_data));
        if (!th_data)
            return NULL;
        a_db_reset_th_data(th_data);
    }

    /**
     * Register thread using DB
     */
    db->th_pool[A_DB_THREAD_CHECKPOINTER].status = A_DB_BG_TH_RUNNING;
    atomic_fetch_add(&db->ref_cnt, 1);
    pthread_cleanup_push(a_db_checkpoint_th_cleanup, arg);

    pthread_barrier_wait(&barrier);

    shutdown = false;
    pthread_mutex_lock(&db->checkpoint_ctx.lock);

    for (;;) {
        while (db->checkpoint_ctx.nr_of_reqs == 0) {
            ts.tv_sec = time(NULL) + A_DB_CHECKPOINTER_INTERVAL;
            ts.tv_nsec = 0;

            rv = pthread_cond_timedwait(&db->checkpoint_ctx.cond, &db->checkpoint_ctx.lock, &ts);
            if (rv != 0 && rv != ETIMEDOUT)
                goto out;

            if (rv == ETIMEDOUT)
                timedout = true;

            break;
        }

        if (db->checkpoint_ctx.flags & A_DB_CHECKPOINT_SHUTDOWN)
            shutdown = true;

        /**
         * Store the set flags
         * Reset count, if a requester is not
         * satisfied in this round, they will just
         * have to request again.
         */
        flags = db->checkpoint_ctx.flags;
        db->checkpoint_ctx.nr_of_reqs = 0;
        db->checkpoint_ctx.flags = A_DB_NIL_FLAGS;
        db->checkpoint_ctx.active = true;

        pthread_mutex_unlock(&db->checkpoint_ctx.lock);

        if (shutdown)
            break;

        do_checkpoint = false;
        if (rv == ETIMEDOUT) {
            do_checkpoint = true;
            flags |= A_DB_CHECKPOINT_TIMED;
        } else if (flags) {
            do_checkpoint = true;
        }

        if (do_checkpoint) {
            off = a_db_create_checkpoint(db, th_data, flags);
            if (off < 0) {
                break;
            }

            /* Checkpoint did not happen */
            if (off == 0)
                continue;

            last_checkpoint_lsn = off;
            last_important_lsn = off;

            /* Alert threads waiting on checkpoint */
            pthread_mutex_lock(&db->checkpoint_ctx.lock);
            db->checkpoint_ctx.ckpt_done = true;
            db->checkpoint_ctx.active = false;
            pthread_cond_signal(&db->checkpoint_ctx.done);
            pthread_mutex_unlock(&db->checkpoint_ctx.lock);
        }
    }

    if (shutdown) {
        off = a_db_create_checkpoint(db, th_data, flags);

        /* Alert shutdown thread waiting on checkpoint */
        pthread_mutex_lock(&db->checkpoint_ctx.lock);
        db->checkpoint_ctx.ckpt_done = true;
        db->checkpoint_ctx.active = false;
        pthread_cond_signal(&db->checkpoint_ctx.done);
        pthread_mutex_unlock(&db->checkpoint_ctx.lock);
    }

out:
    pthread_cleanup_pop(1);
    return NULL;
}

static struct aura_db_rec_table {
    struct {
        int64_t tx_id;
        uint64_t last_lsn;
        uint8_t state;
    } *ent;
    uint32_t cnt;
    uint32_t cap;
} recovery_tab;

static int a_db_insert_recovery_table(uint64_t tx_id, uint64_t last_lsn) {
    if (recovery_tab.cnt >= recovery_tab.cap) {
        recovery_tab.cap = recovery_tab.cap == 0 ? 16 : recovery_tab.cap * 2;
        recovery_tab.ent = realloc(recovery_tab.ent, sizeof(*(recovery_tab.ent)) * recovery_tab.cap);
        if (!recovery_tab.ent)
            return -1;
    }

    recovery_tab.ent[recovery_tab.cnt].last_lsn = last_lsn;
    recovery_tab.ent[recovery_tab.cnt].tx_id = tx_id;
    recovery_tab.ent[recovery_tab.cnt].state = A_DB_TX_ABORTED;
}

static int a_db_tx_id_in_recovery_tab(uint64_t tx_id) {
    for (int i = 0; i < recovery_tab.cnt; ++i) {
        if (recovery_tab.ent[i].tx_id == tx_id)
            return true;
    }

    return false;
}

static int a_db_replay_analysis_pass(AURA_DB *db, lsn_t redo_lsn, uint64_t wal_end) {
    struct aura_db_checkpoint_begin *begin_ckpt;
    struct aura_db_commit *commit;
    struct aura_db_checkpoint *chkpt;
    struct aura_db_wal_rec_hdr log_hdr;
    struct aura_db_rec_hdr *rec_hdr;
    ssize_t rv;
    int tab_idx;
    uint8_t *record = NULL;
    uint64_t rec_size = 4096;

    while (redo_lsn < wal_end) {
        if (pread(db->wal.fd, &log_hdr, sizeof(log_hdr), redo_lsn) != sizeof(log_hdr))
            return -1;

        if (log_hdr.tx_id != A_DB_NIL_TX_ID && a_db_tx_id_in_recovery_tab(log_hdr.tx_id) == 0) {
            tab_idx = a_db_insert_recovery_table(log_hdr.tx_id, log_hdr.lsn);
            if (tab_idx < 0) {
                goto err;
            }
        }

        switch (log_hdr.type) {
        case A_DB_LOG_TYPE_UPDATE:
            recovery_tab.ent[tab_idx].last_lsn = log_hdr.lsn;
            break;

        case A_DB_LOG_TYPE_BEGIN_CKPT:
            /* Incomplete checkpoint, ignore */
            break;

        case A_DB_LOG_TYPE_END_CKPT:
            /* Read checkpoint record */
            if (!record || rec_size < log_hdr.rec_len) {
                rec_size = a_max(rec_size, log_hdr.rec_len);
                record = realloc(record, rec_size);
                if (!record) {
                    goto err;
                }
                memset(record, 0, rec_size);
            }

            if (pread(db->wal.fd, record, log_hdr.rec_len, redo_lsn) != log_hdr.rec_len)
                goto err;

            rec_hdr = (struct aura_db_rec_hdr *)(record + sizeof(log_hdr));
            chkpt = (struct aura_db_checkpoint *)((char *)rec_hdr + sizeof(*rec_hdr) + rec_hdr->key_len);

            for (int i = 0; i < A_DB_MAX_CONC_TX; ++i) {
                if (chkpt->trans[i].id != A_DB_NIL_TX_ID && a_db_tx_id_in_recovery_tab(chkpt->trans[i].id) == 0) {
                    tab_idx = a_db_insert_recovery_table(chkpt->trans[i].id, chkpt->trans[i].last_lsn);
                    if (tab_idx < 0) {
                        goto err;
                    }
                }
            }
            break;

        case A_DB_LOG_TYPE_COMMIT:
            /* Read the rest of the record */
            if (!record || rec_size < log_hdr.rec_len) {
                rec_size = a_max(rec_size, log_hdr.rec_len);
                record = realloc(record, rec_size);
                if (!record) {
                    goto err;
                }
                memset(record, 0, rec_size);
            }

            if (pread(db->wal.fd, record, log_hdr.rec_len, redo_lsn) != log_hdr.rec_len)
                goto err;

            rec_hdr = (struct aura_db_rec_hdr *)(record + sizeof(log_hdr));
            commit = (struct aura_db_commit *)((char *)rec_hdr + sizeof(*rec_hdr) + rec_hdr->key_len);

            recovery_tab.ent[tab_idx].state = commit->state;
            recovery_tab.ent[tab_idx].last_lsn = log_hdr.lsn;
            break;

        default:
            break;
        }

        redo_lsn += log_hdr.rec_len;
    }

    return 0;

err:
    if (record)
        free(record);
    free(recovery_tab.ent);
    return -1;
}

static int a_db_replay_redo_pass(AURA_DB *db, uint64_t redo_lsn, uint64_t wal_end) {
    struct aura_db_wal_rec_hdr log_hdr;
    struct aura_db_rec_hdr *rec_hdr;
    uint8_t *record = NULL;
    uint64_t rec_sz = 4096;
    int fd = db->main.fd;
    lsn_t prev_lsn;
    uint64_t buf_sz = 8192;
    char buf[buf_sz];
    uint64_t buf_off = 0;

    if (lseek(fd, 0, SEEK_END) < 0)
        return -1;

    while (redo_lsn < wal_end) {
        if (pread(db->wal.fd, &log_hdr, sizeof(log_hdr), redo_lsn) != sizeof(log_hdr))
            return -1;

        switch (log_hdr.type) {
        case A_DB_LOG_TYPE_UPDATE:
            /* Read the rest of the record */
            if (!record || rec_sz < log_hdr.rec_len) {
                rec_sz = a_max(rec_sz, log_hdr.rec_len);
                record = realloc(record, rec_sz);
                if (!record) {
                    goto err;
                }
                memset(record, 0, rec_sz);
            }

            if (pread(db->wal.fd, record, log_hdr.rec_len, log_hdr.rec_len) != log_hdr.rec_len)
                goto err;

            /* Update record chain and hash bucket */
            rec_hdr = (struct aura_db_rec_hdr *)(record + sizeof(log_hdr));
            rec_hdr->prev_off = db->control.buckets[rec_hdr->hash].head_off;
            rec_hdr->rec_off = db->control.file_size;
            db->control.buckets[rec_hdr->hash].head_off = rec_hdr->rec_off;
            db->control.file_size += rec_hdr->rec_len.aligned_len;
            db->control.record_cnt++;
            db->control.last_rec_lsn = rec_hdr->rec_off;

            /**
             * This already exists in the main db
             */
            if (rec_hdr->rec_off <= db->control.last_rec_lsn) {
                break;
            }

            /* Too big or equal to buffer */
            if (rec_hdr->rec_len.aligned_len >= buf_sz) {
                if (write(fd, (void *)rec_hdr, rec_hdr->rec_len.aligned_len) != rec_hdr->rec_len.aligned_len)
                    goto err;
            } else if ((buf_sz - buf_off) >= rec_hdr->rec_len.aligned_len) {
                /* Flush buffer */
                if (write(fd, buf, buf_off) != buf_off)
                    goto err;
                buf_off = 0;
            }

            /* copy to buffer */
            memcpy(buf + buf_off, (void *)rec_hdr, rec_hdr->rec_len.aligned_len);
            buf_off += rec_hdr->rec_len.aligned_len;

            break;

        case A_DB_LOG_TYPE_BEGIN_CKPT:
        case A_DB_LOG_TYPE_END_CKPT:
        case A_DB_LOG_TYPE_COMMIT:
        default:
            break;
        }

        redo_lsn += log_hdr.rec_len;
    }

    /* Flush anything remaining */
    if (buf_off > 0)
        if (write(fd, buf, buf_off) != buf_off)
            goto err;
    fdatasync(db->main.fd);

    /* Update control */
    if (a_db_meta_write(db->ctrl_file_fd, (void *)&db->control, sizeof(db->control)) < 0)
        return -1;
    fdatasync(db->ctrl_file_fd);

    free(record);
    return 0;

err:
    if (record)
        free(record);
    return -1;
}

/**
 * Replay log file during recovery
 */
static int a_db_replay(AURA_DB *db) {
    struct aura_db_checkpoint *chkpt;
    struct aura_db_wal_rec_hdr log_hdr;
    struct aura_db_th_data *th_data;
    lsn_t chkpt_lsn, redo_lsn;

    a_db_update_state(db, A_DB_STATE_RECOVERY);
    th_data = pthread_getspecific(thread_key);
    if (!th_data) {
        th_data = calloc(1, sizeof(*th_data));
        if (!th_data)
            return -1;
    }
    a_db_reset_th_data(th_data);

    chkpt = &db->control.chkpt_copy;
    /**
     * No check was saved.
     * Scan starts from the beginning
     */
    if (!chkpt) {
        redo_lsn = 0;
    } else {
        /* Read begin checkpoint record */
        chkpt_lsn = chkpt->redo_lsn;
        if (pread(db->wal.fd, &log_hdr, sizeof(log_hdr), chkpt_lsn) != sizeof(log_hdr))
            return -1;

        /* Start from the next record after begin ckpt */
        redo_lsn += log_hdr.rec_len;
    }

    if (a_db_replay_analysis_pass(db, redo_lsn, db->wal.file_sz) < 0) {
        app_debug(true, 0, "Failed to recover DB");
        return -1;
    }

    if (a_db_replay_redo_pass(db, redo_lsn, db->wal.file_sz) < 0) {
        app_debug(true, 0, "Failed to recover DB");
        return -1;
    }

    if (a_db_create_checkpoint(db, th_data, A_DB_CHECKPOINT_RECOVERY) < 0) {
        app_debug(true, 0, "Failed to replay WAL recovery checkpoint error");
        return -1;
    }

    return 0;
}

/* ============================================ */
static void a_db_write_cache_scan(struct aura_db_write_cache *cache) {
    struct aura_db_cache_buf *active_buf;
    struct aura_db_rec_hdr *rec_hdr;
    uint64_t off = 0;

    active_buf = &cache->bufs[cache->active_idx];
    app_debug(true, 0, "AURA_DB WRITE CACHE DUMP");
    app_debug(true, 0, "--------------------------");
    app_debug(true, 0, "ACTIVE IDX=%u", cache->active_idx);
    app_debug(true, 0, "NEXT OFF=%lu", cache->next_off);
    app_debug(true, 0, "------------------------");
    app_debug(true, 0, "ACTIVE BUF_SZ=%u", active_buf->size);
    app_debug(true, 0, "ACTIVE BUF FLAGS=%u", active_buf->flags);

    while (off < active_buf->size) {
        rec_hdr = (struct aura_db_rec_hdr *)(active_buf->data + off);
        a_db_rec_hdr_dump(rec_hdr);
        off += rec_hdr->rec_len.aligned_len;
    }
}

/* Print single db record header */
static void a_db_rec_hdr_dump(struct aura_db_rec_hdr *hdr) {
    app_debug(true, 0, "AURA DB RECORD HEADER");
    app_debug(true, 0, "    Magic: %x", hdr->magic);
    app_debug(true, 0, "    Namespace: %u", hdr->ns);
    app_debug(true, 0, "    Schema Id: %u", hdr->schema_id);
    app_debug(true, 0, "    Job Id: %lu", hdr->tx_id);
    app_debug(true, 0, "    Prev TX Rec off: %ld", hdr->prev_tx_rec_off);
    app_debug(true, 0, "    Flags: %u", hdr->flags);
    app_debug(true, 0, "    Key len: %u", hdr->key_len);
    app_debug(true, 0, "    Data len: %u", hdr->data_len);
    app_debug(true, 0, "    Record len: %u", hdr->rec_len.aligned_len);
    app_debug(true, 0, "    Previous offset: %u", hdr->prev_off);
    app_debug(true, 0, "    Timestamp: %u", hdr->timestamp_ms);
}

static char *a_db_get_op(uint16_t op) {
    switch (op) {
    case A_DB_INSERT_OP:
        return "OP Insert";
    case A_DB_DELETE_OP:
        return "OP Delete";
    case A_DB_JOB_CREATE_OP:
        return "OP Job create";
    case A_DB_JOB_EVENT_OP:
        return "OP Job event";
    case A_DB_JOB_STEP_OP:
        return "OP Job Step";
    default:
        return "Unknown OP";
    }
}

/* Print single WAL record header */
static void a_db_wal_hhdr_dump(struct aura_db_wal_rec_hdr *hdr) {
    app_debug(true, 0, "AURA DB WAL RECORD HEADER");
    app_debug(true, 0, "    Magic: %x", hdr->magic);
    app_debug(true, 0, "    Op: %u: %s", hdr->op, a_db_get_op(hdr->op));
    app_debug(true, 0, "    Record len: %lu", hdr->rec_len);
}

void aura_db_wal_scan(AURA_DBHANDLE _db) {
    AURA_DB *db;
    struct aura_db_wal_rec_hdr wal_hdr;
    struct aura_db_rec_hdr rec_hdr;
    off_t offset;
    ssize_t res;

    db = (AURA_DB *)_db;
    // offset = sizeof(struct aura_db_wal_hdr);

    // app_debug(true, 0, "WAL FILE HEADER");
    // app_debug(true, 0, "    Magic: %u", db->wal_file_hdr.magic);
    // app_debug(true, 0, "    Flags: %u", db->wal_file_hdr.flags);
    // app_debug(true, 0, "    Created: %lu", db->wal_file_hdr.created_ms);
    // app_debug(true, 0, "    Last replay: %lu", db->wal_file_hdr.last_replay_ms);
    // app_debug(true, 0, "    Record cnt: %lu", db->wal_file_hdr.record_cnt);

    // while (true) {
    //     app_debug(true, 0, "wal DB read offset: %u", offset);
    //     res = pread(db->wal_fd, &wal_hdr, sizeof(wal_hdr), offset);
    //     if (res == 0)
    //         break;
    //     res = pread(db->wal_fd, &rec_hdr, sizeof(rec_hdr), offset + sizeof(wal_hdr));

    //     a_db_wal_hhdr_dump(&wal_hdr);
    //     a_db_rec_hdr_dump(&rec_hdr);
    //     offset += wal_hdr.rec_len;
    // }
}

void aura_db_scan(AURA_DBHANDLE _db) {
    AURA_DB *db;
    struct aura_db_rec_hdr rec_hdr;
    off_t offset;
    ssize_t res;

    db = (AURA_DB *)_db;
    // offset = db->db_file_hdr.record_off;

    // app_debug(true, 0, "DB file size: %u", db->db_file_hdr.file_size);
    // while (offset < db->db_file_hdr.file_size) {
    //     app_debug(true, 0, "DB read offset: %u", offset);
    //     res = pread(db->db_fd, &rec_hdr, sizeof(rec_hdr), offset);

    //     a_db_rec_hdr_dump(&rec_hdr);
    //     offset += rec_hdr.rec_len.aligned_len;
    // }
}

/**/
AURA_DBHANDLE aura_db_test_open_with_log_writer(struct aura_mem_ctx *mc, const char *db_path, int oflag,
                                                uint32_t wrt_cache_sz, uint32_t read_cache_sz, ...) {
    AURA_DB *db;
    int mode;

    va_list va;
    va_start(va, read_cache_sz);
    mode = va_arg(va, int);
    va_end(va);

    db = a_db_open(mc, db_path, oflag, mode, wrt_cache_sz, read_cache_sz);
    a_db_update_state(db, A_DB_STATE_RUNNING);

    /* log writer and main threads */
    pthread_barrier_init(&barrier, NULL, 2);

    a_db_start_bg_thread(db, A_DB_THREAD_WAL_WRITER);

    pthread_barrier_wait(&barrier);

    return db;
}

void aura_db_test_fields_with_bg_writer(AURA_DBHANDLE _db) {
    AURA_DB *db = _db;
    assert(db->th_pool[A_DB_THREAD_WAL_WRITER].status == A_DB_BG_TH_RUNNING);
    assert(db->ref_cnt == 1);
}

void aura_db_test_close_with_bg_writer(AURA_DBHANDLE _db) {
    AURA_DB *db = _db;

    pthread_cancel(db->th_pool[A_DB_THREAD_WAL_WRITER].handle);

    pthread_join(db->th_pool[A_DB_THREAD_WAL_WRITER].handle, NULL);

    _a_db_close(db);
    free((void *)db->file_name);
    free(db);
}

int aura_db_test_force_write_cache_flush(AURA_DBHANDLE _db) {
    AURA_DB *db = _db;
    return a_db_write_cache_flush(db, A_DB_WRITE_CACHE_FLUSH_FORCE);
}

void aura_db_test_write_cache_reset(AURA_DBHANDLE _db) {
    AURA_DB *db = _db;
    struct aura_db_write_cache *cache = &db->cache.wrt_cache;
    struct aura_db_cache_buf *buf;

    pthread_mutex_lock(&cache->lock);
    buf = &cache->bufs[cache->active_idx];
    a_db_reset_cache_buf(buf);

    buf = &cache->bufs[1 - cache->active_idx];
    a_db_reset_cache_buf(buf);
    pthread_mutex_unlock(&cache->lock);
}

int aura_db_test_fetch_from_write_cache(AURA_DBHANDLE _db, ns_t namespace, schema_id_t schema_id,
                                        struct aura_iovec *key, struct aura_db_rec *data_out) {
    AURA_DB *db = _db;
    uint32_t hash;

    hash = a_fnv1a_hash(A_DB_HASH_BUCKET_CNT, namespace, key);

    if (data_out) {
        memset(data_out, 0, sizeof(*data_out));
    }

    return a_db_write_cache_fetch(db, namespace, schema_id, key, hash, data_out);
}

int aura_db_test_fetch_db(AURA_DBHANDLE _db, ns_t namespace, schema_id_t schema_id,
                          struct aura_iovec *key, struct aura_db_rec *data_out) {
    AURA_DB *db = _db;
    uint32_t hash;

    hash = a_fnv1a_hash(A_DB_HASH_BUCKET_CNT, namespace, key);

    if (data_out) {
        memset(data_out, 0, sizeof(*data_out));
    }

    return a_db_fetch(db, namespace, schema_id, key, data_out);
}