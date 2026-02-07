#include "db/db.h"
#include "file_lib.h"
#include "hash_lib.h"
#include "list_lib.h"
#include "memory_lib.h"
#include "slab_lib.h"
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

/* DB header structure */
struct aura_db_hdr {
    uint32_t magic;
    uint16_t version;
    uint16_t flags;
    uint64_t created_ts;
    uint64_t last_compact_ts;
    uint64_t last_rec_off; /* Record of last rec offset */
    uint32_t hash_algo;
    uint32_t bucket_cnt;
    off_t bucket_off;
    off_t record_off;
    uint64_t lsn; /* Next record to be applied from WAL to DB */
    uint64_t file_size;
    uint64_t record_cnt;
    uint64_t wasted_bytes; /* total deleted records in the db */
};

enum {
    A_DB_REPLAY_MODE_RECOVERY,
    A_DB_REPLAY_MODE_NORMAL
};

/* WAL header structure */
struct aura_db_wal_hdr {
    uint32_t magic;
    uint16_t version;
    uint16_t flags;
    uint64_t created_ts;
    uint64_t last_replay_ts;
    uint64_t last_file_offset;
    uint64_t record_cnt;
};

struct aura_db_writer_queue {
    pthread_mutex_t mutex;
    pthread_cond_t cond;
    struct aura_list_head db_list;
};

#define A_DB_MAGIC 0x5D5D5D5D
#define A_DB_REC_MAGIC 0xED5EC001
#define A_DB_WAL_MAGIC 0xED3A1001
#define A_BUCKET_TAB_OFFSET sizeof(struct aura_db_hdr)
#define A_DB_BUF_SIZE 4096
#define A_DB_REC_BUF_SIZE (32 * 1024) /* 32KB */
#define A_DB_VERSION 0x10000U
#define A_DB_CHK_PNT_MAGIC 0xC3C3C3C3
#define A_DB_CHECK_PNT_RECORD_KEY "replay_checkpt"

/**
 * @todo: A dedicated write thread with writer queue might be better
 */

/* Record len structure */
struct aura_db_rec_len {
    size_t raw_len;     /* Exact record length not aligned */
    size_t aligned_len; /* Record len aligned */
};

/* record header structure */
struct aura_db_rec_hdr {
    uint32_t magic;
    uint32_t version;
    uint16_t ns; /* namespace */
    uint16_t schema_id;
    uint16_t flags;
    uint64_t job_id;       /* Points to the job this record is bracketed under, helps with small transaction stuff */
    uint64_t prev_job_rec; /* Previous record associated with this job */
    struct aura_db_rec_len rec_len;
    uint32_t key_len;
    uint32_t data_len;
    uint64_t timestamp;
    uint64_t prev_off; /* link for bucket chain */
    char check_sum[DIGEST_LEN];
}; /* [key][data][padding] */

/* Bucket offset entry */
struct aura_db_bucket_entry {
    _Atomic off_t head_off; /* offset of newest record */
};

/* WAL record header structure */
struct aura_db_wal_rec_hdr {
    uint32_t magic;
    uint16_t op;
    uint64_t rec_len;
    uint64_t lsn;
}; /* [record] */

/*
 * Library's private representation of the database.
 */
typedef struct {
    int db_fd;  /* fd for db file */
    int wal_fd; /* fd for WAL file */
    char *name; /* database file name */
    struct aura_memory_ctx *mc;
    struct aura_db_hdr db_file_hdr;      /* database header */
    struct aura_db_wal_hdr wal_file_hdr; /* WAL file header */
    // struct aura_db_shared_hdr *sh_hdr;        /* process shared database header */
    struct aura_db_bucket_entry *buckets;     /* hash buckets */
    void *record_buf;                         /* In memory record buffer */
    size_t record_buf_size;                   /* Size of record buffer */
    off_t append_off;                         /* In memory append offset */
    size_t curr_file_size;                    /* Local cache main db file size (updated on every wal replay and compact) */
    pthread_mutex_t db_lock;                  /* Memory lock for in memory structure */
    pthread_cond_t db_cond;                   /* DB conditional variable */
    bool is_busy;                             /* DB is busy with replay or compaction */
    bool shutdown;                            /* Signal for db to shutdown */
    struct aura_db_writer_queue writer_queue; /* All db writes go through this */
    uint32_t cnt_del_ok;                      /* delete OK */
    uint32_t cnt_del_err;                     /* delete error */
    uint32_t cnt_fetch_ok;                    /* fetch OK */
    uint32_t cnt_fetch_err;                   /* fetch error */
    uint32_t cnt_stor_ok;                     /* store OK */
    uint32_t cnt_stor_err;                    /* store error */
} AURA_DB;

/* Checkpoint record structure */
struct aura_db_pending_job {
    uint64_t job_id;
    uint16_t job_state;
    uint16_t job_type;
};

struct aura_db_pending_job_rec {
    uint64_t job_id;
    off_t rec_off;
    size_t rec_len;
};

/* Check point rec structure */
struct aura_db_checkpoint_rec {
    uint32_t version;
    uint32_t magic;
    uint64_t lsn;
    size_t pending_job_cnt;
    size_t pending_job_rec_cnt;
    struct aura_db_pending_job *pending_jobs;
    struct aura_db_pending_job_rec *pending_job_records;
}; /* [replay tab] */

/*
 * Internal functions.
 */
static AURA_DB *a_db_alloc(int);
static void a_db_free(AURA_DB *);
static off_t a_db_wal_commit(int wal_fd, int wal_op, struct aura_db_rec_hdr *hdr,
                             struct aura_iovec *key, struct aura_iovec *data);
static int a_db_wal_replay(AURA_DB *);
static int a_db_compact(AURA_DB *db);
/* Dump database header */
static void a_db_dump_header(struct aura_db_hdr *);
/* Print wal record header */
static void a_db_dump_wal_header(struct aura_db_wal_rec_hdr *);
/* Print record header */
static void a_db_dump_rec_header(struct aura_db_rec_hdr *);
/**/
static void a_db_job_dump(struct aura_db_job_rec *);
/**/
static void a_db_check_pnt_rec_dump(struct aura_db_checkpoint_rec *);

/**
 * Get record size possibly 8-byte aligned
 */
static inline struct aura_db_rec_len a_get_db_record_len(size_t key_len, size_t data_len) {
    struct aura_db_rec_len len;

    len.raw_len = sizeof(struct aura_db_rec_hdr) + key_len + data_len;
    len.aligned_len = A_ALIGN(len.raw_len, sizeof(void *));
    return len;
}

/* Calculate key hash */
static inline uint32_t a_fnv1a_hash(uint32_t bucket_cnt, uint16_t namespace, struct aura_iovec *key) {
    uint32_t hash, hash_val;

    hash_val = FNV1_32A_INIT;
    hash_val ^= (uint32_t)namespace;
    hash = fnv_32a_buf((void *)key->base, key->len, hash_val);
    hash &= (bucket_cnt - 1);
    return hash;
}

static inline void a_db_rewind(int fd) {
    off_t res;

    /* Back to beginning for now */
    res = lseek(fd, 0, SEEK_SET);
    if (res < 0)
        sys_exit(true, errno, "a_db_rewind error");
}

/*
 * Allocate & initialize a DB structure and its buffers.
 */
static AURA_DB *a_db_alloc(int namelen) {
    AURA_DB *db;
    size_t bucket_arr_size;

    db = calloc(1, sizeof(AURA_DB));
    if (!db)
        goto exception;
    /* init db file descriptor */
    db->db_fd = -1;

    /* Null terminated string */
    db->name = malloc(namelen + 1);
    if (!db->name)
        goto exception;
    memset(db->name, 0, namelen + 1);

    db->record_buf = malloc(A_DB_REC_BUF_SIZE);
    if (!db->record_buf)
        goto exception;
    db->record_buf_size = A_DB_REC_BUF_SIZE;
    memset(db->record_buf, 0, A_DB_REC_BUF_SIZE);

    bucket_arr_size = sizeof(struct aura_db_bucket_entry) * A_DB_BUCKET_CNT;
    db->buckets = malloc(bucket_arr_size);
    if (!db->buckets)
        goto exception;
    memset(db->buckets, 0, bucket_arr_size);
    db->shutdown = false;
    db->is_busy = false;
    db->append_off = 0;

    return db;
exception:
    sys_exit(true, errno, "a_db_alloc: error");
}

/**
 * Save db meta data
 * Pass an immutable memory to this function
 */
static inline ssize_t a_db_meta_write(int fd, struct iovec *hdr, struct iovec *bucket) {
    struct iovec iov[2];

    if (lseek(fd, 0, SEEK_SET) < 0)
        return -1;

    iov[0].iov_base = hdr->iov_base;
    iov[0].iov_len = hdr->iov_len;
    iov[1].iov_base = bucket->iov_base;
    iov[1].iov_len = bucket->iov_len;

    return writev(fd, iov, 2);
}

static inline ssize_t a_db_read_hash_table(int fd, struct iovec *bucket) {
    if (lseek(fd, 0, SEEK_SET) < 0)
        return -1;

    return write(fd, bucket->iov_base, bucket->iov_len);
}

/**
 * Read db meta data
 * This is called only on startup for now
 * So there may not be need to lock!
 */
static inline ssize_t a_db_meta_read(int fd, struct iovec *hdr, struct iovec *bucket) {
    struct iovec iov[2];

    if (lseek(fd, 0, SEEK_SET) < 0)
        return -1;

    iov[0].iov_base = hdr->iov_base;
    iov[0].iov_len = hdr->iov_len;
    iov[1].iov_base = bucket->iov_base;
    iov[1].iov_len = bucket->iov_len;

    return readv(fd, iov, 2);
}

static inline int a_db_file_open(int dir_fd, const char *filename, int *flags, int mode) {
    int fd;

    if (*flags & O_CREAT) {
        fd = openat(dir_fd, filename, *flags, mode);

        if (fd < 0) {
            if (errno != EEXIST)
                return -1;

            if (errno == EEXIST) {
                /* Open normally */
                *flags &= ~(O_CREAT | O_TRUNC | O_EXCL);
                fd = openat(dir_fd, filename, *flags);
            }
        }
    } else {
        fd = openat(dir_fd, filename, *flags);
    }

    return fd;
}

static inline int a_db_headers_init(AURA_DB *db, size_t file_size) {
    uint64_t created_ts;

    created_ts = aura_now_ms(CLOCK_REALTIME);

    db->db_file_hdr.magic = A_DB_MAGIC;
    db->db_file_hdr.version = (uint16_t)0x10000; /* 1.0.0 */
    db->db_file_hdr.hash_algo = A_FNV1A_HASH_ALGO;
    db->db_file_hdr.created_ts = created_ts;
    db->db_file_hdr.flags = 0;
    db->db_file_hdr.last_compact_ts = 0;
    db->db_file_hdr.bucket_cnt = A_DB_BUCKET_CNT;
    db->db_file_hdr.bucket_off = A_BUCKET_TAB_OFFSET;
    db->db_file_hdr.record_off = A_BUCKET_TAB_OFFSET + (A_DB_BUCKET_CNT * sizeof(void *));
    db->db_file_hdr.file_size = file_size;
    db->db_file_hdr.record_cnt = 0;
    db->db_file_hdr.last_rec_off = 0;
    db->db_file_hdr.lsn = 0;

    db->wal_file_hdr.flags = 0;
    db->wal_file_hdr.magic = A_DB_WAL_MAGIC;
    db->wal_file_hdr.version = (uint16_t)0x10000;
    db->wal_file_hdr.created_ts = created_ts;
    db->wal_file_hdr.last_file_offset = 0;
    db->wal_file_hdr.last_replay_ts = created_ts;
    db->wal_file_hdr.record_cnt = 0;

    return 0;
}

/*
 * Open or create a database.  Structured similar to open(2).
 */
AURA_DBHANDLE aura_db_open(struct aura_memory_ctx *mc, const char *app_path, const char *db_pathname, int oflag, ...) {
    AURA_DB *db;
    DIR *dp;
    int db_namelen, mode, dir_fd;
    size_t bucket_arr_size;
    struct stat statbuf;

    /* Allocate a DB structure, and the buffers it needs. */
    db_namelen = strlen(db_pathname);
    db = a_db_alloc(db_namelen);
    if (!db)
        sys_exit(true, errno, "aura_db_open error");
    strcpy(db->name, db_pathname);
    db->mc = mc;

    if (pthread_mutex_init(&db->db_lock, NULL) != 0)
        goto err_close;

    if (pthread_cond_init(&db->db_cond, NULL) != 0)
        goto err_close;

    if (pthread_mutex_init(&db->writer_queue.mutex, NULL) != 0)
        goto err_close;

    if (pthread_cond_init(&db->writer_queue.cond, NULL) != 0)
        goto err_close;

    dp = NULL;
    dp = opendir(app_path);
    if (!dp)
        sys_exit(true, errno, "aura_db_open: opendir");

    dir_fd = dirfd(dp);
    if (dir_fd < 0)
        sys_exit(true, errno, "aura_db_open: dirfd error");

    va_list ap;

    va_start(ap, oflag);
    mode = va_arg(ap, int);
    va_end(ap);

    /* init writer queue */
    a_list_head_init(&db->writer_queue.db_list);

    /* database file */
    db->db_fd = a_db_file_open(dir_fd, AURA_DB_FILE, &oflag, mode);
    if (db->db_fd < 0)
        goto err_close;

    /* wal file */
    db->wal_fd = a_db_file_open(dir_fd, AURA_DB_WAL_FILE, &oflag, mode);
    if (db->wal_fd < 0)
        goto err_close;

    bucket_arr_size = sizeof(struct aura_db_bucket_entry) * A_DB_BUCKET_CNT;
    size_t file_size = sizeof(struct aura_db_hdr) + bucket_arr_size;
    if ((oflag & (O_CREAT | O_TRUNC)) == (O_CREAT | O_TRUNC)) {
        /*
         * If the database was created, we have to initialize
         * it.  Write lock the entire file so that we can stat
         * it, check its size, and initialize it, atomically.
         */
        if (fstat(db->db_fd, &statbuf) < 0)
            sys_exit(true, errno, "db_open: fstat error");

        if (statbuf.st_size == 0) {
            /* Initialize db header */
            a_db_headers_init(db, file_size);

            /* Store current file size */
            db->curr_file_size = file_size;

            struct iovec hdr, bucket;
            hdr.iov_base = &db->db_file_hdr;
            hdr.iov_len = sizeof(struct aura_db_hdr);
            bucket.iov_base = db->buckets;
            bucket.iov_len = bucket_arr_size;

            if (a_db_meta_write(db->db_fd, &hdr, &bucket) <= 0)
                sys_exit(true, errno, "db_open: db file init write error");

            hdr.iov_base = &db->wal_file_hdr;
            hdr.iov_len = sizeof(struct aura_db_wal_hdr);
            bucket.iov_base = NULL;
            bucket.iov_len = 0;

            if (a_db_meta_write(db->wal_fd, &hdr, &bucket) <= 0)
                sys_exit(true, errno, "db_open: db file init write error");
        }
    } else {
        /* read db hdr and buckets into their buffers */
        if (lseek(db->db_fd, 0, SEEK_SET) < 0)
            goto err_close;

        struct iovec hdr_iov, bucket_iov;

        /* Read db header */
        hdr_iov.iov_base = &db->db_file_hdr;
        hdr_iov.iov_len = sizeof(struct aura_db_hdr);
        bucket_iov.iov_base = db->buckets;
        bucket_iov.iov_len = bucket_arr_size;
        if (a_db_meta_read(db->db_fd, &hdr_iov, &bucket_iov) <= 0)
            goto err_close;

        /* Read wal header */
        hdr_iov.iov_base = &db->wal_file_hdr;
        hdr_iov.iov_len = sizeof(struct aura_db_wal_hdr);
        bucket_iov.iov_base = NULL;
        bucket_iov.iov_len = 0;
        if (a_db_meta_read(db->wal_fd, &hdr_iov, &bucket_iov) <= 0) {
            goto err_close;
        }

        /* Store current file size */
        db->curr_file_size = db->db_file_hdr.file_size;
    }

    closedir(dp);
    a_db_rewind(db->db_fd);
    return db;

err_close:
    if (dp)
        closedir(dp);
    a_db_free(db);
    return NULL;
}

/*
 * Free up a DB structure, and all the malloc'ed buffers it
 * may point to.  Also close the file descriptors if still open.
 */
static void a_db_free(AURA_DB *db) {
    if (db->db_fd >= 0)
        close(db->db_fd);
    if (db->wal_fd >= 0)
        close(db->wal_fd);

    if (db->name != NULL)
        free(db->name);
    if (db->buckets)
        free(db->buckets);
    if (db->record_buf)
        free(db->record_buf);

    pthread_cond_destroy(&db->db_cond);
    pthread_mutex_destroy(&db->db_lock);
    pthread_cond_destroy(&db->writer_queue.cond);
    pthread_mutex_destroy(&db->writer_queue.mutex);
    free(db);
}

/*
 * Relinquish access to the database.
 */
void aura_db_close(AURA_DBHANDLE _db) {
    AURA_DB *db;

    db = (AURA_DB *)_db;
    pthread_mutex_lock(&db->writer_queue.mutex);
    db->shutdown = true;
    pthread_cond_signal(&db->writer_queue.cond);
    pthread_mutex_unlock(&db->writer_queue.mutex);

    a_db_wal_replay(db);
    a_db_free(db);
}

void aura_db_record_free(struct aura_db_rec *rec) {
    if (!rec)
        return;

    aura_free(rec->data.base);
}

static inline off_t a_db_record_append(int fd, struct aura_db_rec_hdr *rec_hdr,
                                       void *key, void *data, off_t start_offset) {
    struct iovec iov[4];
    off_t offset;
    ssize_t written;
    size_t pad_len;
    static const uint64_t db_zero = 0;

    iov[0].iov_base = rec_hdr;
    iov[0].iov_len = sizeof(*rec_hdr);
    iov[1].iov_base = key;
    iov[1].iov_len = rec_hdr->key_len;
    iov[2].iov_base = data;
    iov[2].iov_len = rec_hdr->data_len;

    pad_len = rec_hdr->rec_len.aligned_len - rec_hdr->rec_len.raw_len;
    char pad[pad_len];
    memset(pad, 0, pad_len);
    iov[3].iov_base = (void *)pad;
    iov[3].iov_len = pad_len;

    /* Append the record */
    if (start_offset == 0) {
        offset = lseek(fd, 0, SEEK_END);
    } else {
        offset = lseek(fd, start_offset, SEEK_SET);
    }
    if (offset < 0)
        return offset;

    written = writev(fd, iov, 4);
    if (written != rec_hdr->rec_len.aligned_len)
        return -1;

    return offset;
}

static inline struct aura_db_rec_hdr *a_db_record_cache_fetch(AURA_DB *db, uint16_t namespace, uint16_t schema_id,
                                                              struct aura_iovec *key, off_t offset, uint32_t hash) {
    struct aura_db_rec_hdr *rec_hdr;
    ssize_t res;
    off_t cache_offset;
    const char *key_buf;

    while (offset >= db->curr_file_size) {
        cache_offset = offset - db->curr_file_size;
        rec_hdr = db->record_buf + cache_offset;

        if (rec_hdr->magic != A_DB_REC_MAGIC)
            break;

        if (rec_hdr->ns == namespace && rec_hdr->schema_id == schema_id && rec_hdr->key_len == key->len) {
            key_buf = (char *)rec_hdr + sizeof(*rec_hdr);
            if (aura_mem_is_eq(key_buf, rec_hdr->key_len, key->base, key->len)) {
                if (rec_hdr->flags & A_DB_FLAG_REC_TOMBSTONE)
                    return NULL;

                return rec_hdr;
            }
        }

        offset = rec_hdr->prev_off;
    }

    return NULL;
}

static inline int a_db_record_cache_append(AURA_DB *db, struct aura_db_rec_hdr *rec_hdr,
                                           struct aura_iovec *key, struct aura_iovec *data, uint32_t hash) {
    off_t new_append_off;
    off_t file_offset; /* actual offset in the main db file */

    /* If single record can't fit in cache */
    if (rec_hdr->rec_len.aligned_len > db->record_buf_size) {
        /* Do nothing but update in memory file size */
        pthread_mutex_lock(&db->db_lock);
        db->db_file_hdr.file_size += rec_hdr->rec_len.aligned_len;
        pthread_mutex_unlock(&db->db_lock);
        return 0;
    }

    /* actual file offset given by current main db file size + in memory offset */
    file_offset = db->curr_file_size + db->append_off;
    new_append_off = db->append_off + rec_hdr->rec_len.aligned_len;

    /* If cummulative records can't fit in cache */
    if (new_append_off > db->record_buf_size) {

        /* update new current db file size */
        db->curr_file_size = db->db_file_hdr.file_size;

        /** clear cache and start filling again */
        char *write_ptr = (char *)db->record_buf;
        memset(db->record_buf, 0, db->record_buf_size);
        memcpy(write_ptr, rec_hdr, sizeof(*rec_hdr));
        memcpy(write_ptr + sizeof(*rec_hdr), key->base, rec_hdr->key_len);
        if (data)
            memcpy(write_ptr + sizeof(*rec_hdr) + rec_hdr->key_len, data->base, data->len);
        db->append_off = rec_hdr->rec_len.aligned_len;
    } else {
        char *write_ptr = (char *)db->record_buf + db->append_off;
        memcpy(write_ptr, rec_hdr, sizeof(*rec_hdr));
        memcpy(write_ptr + sizeof(*rec_hdr), key->base, rec_hdr->key_len);
        if (data)
            memcpy(write_ptr + sizeof(*rec_hdr) + rec_hdr->key_len, data->base, data->len);
        db->append_off = new_append_off;
    }

    pthread_mutex_lock(&db->db_lock);
    db->buckets[hash].head_off = file_offset;

    pthread_mutex_unlock(&db->db_lock);
    return 0;
}

/** Construct DB record header */
static inline int64_t a_db_record_header_init(AURA_DB *db, struct aura_db_rec_hdr *rec_hdr, uint16_t namespace, uint16_t schema_id, uint64_t job_id,
                                              uint64_t prev_job_rec, struct aura_iovec *key, struct aura_iovec *data, uint16_t flags) {
    uint32_t hash, old_head;
    struct aura_iovec data_checksum;

    hash = a_fnv1a_hash(db->db_file_hdr.bucket_cnt, namespace, key);
    old_head = db->buckets[hash].head_off;

    data_checksum = aura_calculate_digest(data);
    if (data_checksum.base == NULL && data->base != NULL) {
        app_debug(true, 0, "a_db_init_rec_hdr: aura_calculate_digest error");
        return -1;
    }

    rec_hdr->magic = A_DB_REC_MAGIC;
    rec_hdr->version = A_DB_VERSION;
    rec_hdr->ns = namespace;
    rec_hdr->flags = flags;
    rec_hdr->schema_id = schema_id;
    rec_hdr->prev_off = old_head;
    rec_hdr->job_id = job_id;
    rec_hdr->prev_job_rec = prev_job_rec;
    rec_hdr->timestamp = aura_now_ms(CLOCK_REALTIME);
    rec_hdr->key_len = key->len;
    if (data)
        rec_hdr->rec_len = a_get_db_record_len(key->len, data->len);
    else
        rec_hdr->rec_len = a_get_db_record_len(key->len, 0);
    rec_hdr->data_len = 0;
    if (data)
        rec_hdr->data_len = data->len;
    memcpy(rec_hdr->check_sum, data_checksum.base, DIGEST_LEN);

    return hash;
}

/**
 * Append given record to WAL and cache
 */
static off_t a_db_record_insert_core(AURA_DBHANDLE _db, uint16_t namespace, uint16_t schema_id, uint64_t job_id, uint64_t prev_job_rec,
                                     uint16_t flags, aura_db_op op, struct aura_iovec *key, struct aura_iovec *data) {
    struct aura_db_rec_hdr rec_hdr;
    uint32_t hash;
    AURA_DB *db;
    off_t offset;
    int res;

    db = (AURA_DB *)_db;
    hash = a_db_record_header_init(db, &rec_hdr, namespace, schema_id, job_id, prev_job_rec, key, data, flags);
    if (hash < 0)
        return -1;

    offset = a_db_wal_commit(db->wal_fd, op, &rec_hdr, key, data);
    if (offset < 0) {
        sys_debug(true, errno, "a_db_record_insert_code: a_db_wal_commit error:");
        return offset;
    }

    /* update in memory */
    if (a_db_record_cache_append(db, &rec_hdr, key, data, hash) < 0)
        return -1;

    pthread_mutex_lock(&db->db_lock);
    db->db_file_hdr.record_cnt++;
    if (op == A_DB_OP_DELETE)
        db->db_file_hdr.wasted_bytes += rec_hdr.rec_len.aligned_len;
    pthread_mutex_unlock(&db->db_lock);

    return offset;
}

static int a_db_enqueue_request(AURA_DBHANDLE _db, uint16_t namespace, uint16_t schema_id, uint64_t job_id, uint64_t prev_job_rec,
                                uint16_t flags, aura_db_op op, struct aura_iovec *key, struct aura_iovec *data, struct aura_db_completion *completion) {
    AURA_DB *db;
    struct aura_db_write_req *req;

    db = (AURA_DB *)_db;

    req = calloc(1, sizeof(*req));
    if (!req)
        return -1;

    a_list_head_init(&req->w_list);
    req->namespace = namespace;
    req->schema_id = schema_id;
    req->op = op;
    req->key = key;
    req->job_id = job_id;
    req->prev_job_rec = prev_job_rec;
    req->flags = flags;
    req->data = data;
    req->completion = completion;

    pthread_mutex_lock(&db->writer_queue.mutex);
    a_list_add_tail(&db->writer_queue.db_list, &req->w_list);
    pthread_cond_signal(&db->writer_queue.cond);
    pthread_mutex_unlock(&db->writer_queue.mutex);

    return 0;
}

ssize_t aura_db_record_insert(AURA_DBHANDLE _db, uint16_t namespace, uint16_t schema_id, uint64_t job_id, uint64_t prev_job_rec, aura_db_op op, struct aura_iovec *key,
                              struct aura_iovec *data, aura_db_exec_mode exec_mode, struct aura_db_completion *comp) {
    if (exec_mode == A_DB_EXEC_DIRECT)
        return a_db_record_insert_core(_db, namespace, schema_id, job_id, prev_job_rec, A_DB_FLAG_NONE, op, key, data);
    else
        return a_db_enqueue_request(_db, namespace, schema_id, job_id, prev_job_rec, A_DB_FLAG_NONE, op, key, data, comp);
}

uint64_t aura_db_job_insert(AURA_DBHANDLE _db, uint32_t job_type, uint8_t state, uint64_t timeout, int error,
                            aura_db_exec_mode exec_mode, struct aura_db_completion *completion) {
    AURA_DB *db;
    struct aura_db_job_rec job;
    char job_key[2046], job_step_key[2046];
    struct aura_iovec key, data;
    int res;
    off_t offset;

    db = (AURA_DB *)_db;
    job.created_at = aura_now_ms(CLOCK_REALTIME);
    job.job_id = job.created_at;
    job.job_type = job_type;
    job.last_rec_off = 0;
    job.error_code = error;
    job.version = A_DB_VERSION;
    job.state = state;
    job.ttl_epoch = timeout;

    memset(job_key, 0, sizeof(job_key));
    /* format: job:<jobid> */
    snprintf(job_key, sizeof(job_key) - 1, "job:%lu", job.job_id);

    if (exec_mode == A_DB_EXEC_DIRECT) {
        key.base = job_key;
        key.len = strlen(job_key);
        data.base = (void *)&job;
        data.len = sizeof(job);

        offset = a_db_record_insert_core(db, A_DB_NS_JOB, A_DB_SCHEMA_JOB_V1, 0, 0, A_DB_FLAG_NONE, A_DB_JOB_OP_CREATE, &key, &data);
        if (offset < 0)
            return 0;
    } else if (exec_mode == A_DB_EXEC_ASYNC) {
        struct aura_iovec *key_ptr, *data_ptr;

        key_ptr = aura_iovec_init(db->mc, strlen(job_key), NULL);
        if (!key_ptr)
            return 0;
        data_ptr = aura_iovec_init(db->mc, sizeof(job), NULL);
        if (!data_ptr) {
            aura_iovec_destroy(key_ptr);
            return 0;
        }

        /* Copy over contents for queueing */
        memcpy(key_ptr->base, job_key, key_ptr->len);
        memcpy(data_ptr->base, &job, data_ptr->len);
        res = a_db_enqueue_request(db, A_DB_NS_JOB, A_DB_SCHEMA_JOB_V1, 0, 0, A_DB_FLAG_NONE, A_DB_JOB_OP_CREATE, key_ptr, data_ptr, completion);
        if (res != 0) {
            aura_iovec_destroy(key_ptr);
            aura_iovec_destroy(data_ptr);
            return 0;
        }
    }

    return job.job_id;
}

int aura_db_job_update(AURA_DBHANDLE _db, uint64_t job_id, uint16_t state, int error, uint64_t rec_off,
                       aura_db_exec_mode exec_mode, struct aura_db_completion *comp) {
    AURA_DB *db;
    char buf[1024];
    struct aura_iovec key, data;
    struct aura_db_job_rec *job_rec;
    int res, err;
    off_t offset;

    db = (AURA_DB *)_db;
    job_rec = aura_db_job_fetch(_db, job_id, &err);
    if (!job_rec) {
        return err;
    }

    /* Update new state, last_rec_off and possibly error */
    job_rec->state = state;
    job_rec->error_code = error;
    job_rec->last_rec_off = rec_off;

    memset(buf, 0, sizeof(buf));
    /* same key as current record */
    snprintf(buf, sizeof(buf) - 1, "job:%lu", job_rec->job_id);

    if (exec_mode == A_DB_EXEC_DIRECT) {
        key.base = buf;
        key.len = strlen(buf);
        data.base = (void *)job_rec;
        data.len = sizeof(*job_rec);

        offset = a_db_record_insert_core(db, A_DB_NS_JOB, A_DB_SCHEMA_JOB_V1, 0, 0, A_DB_FLAG_NONE, A_DB_JOB_OP_STEP, &key, &data);
        /* No longer needed */
        aura_free(job_rec);
        if (offset < 0)
            return offset;
        return 0;
    } else if (exec_mode == A_DB_EXEC_ASYNC) {
        struct aura_iovec *key_ptr, *data_ptr;

        key_ptr = aura_iovec_init(db->mc, strlen(buf), NULL);
        if (!key_ptr)
            return -1;
        data_ptr = aura_iovec_init(db->mc, sizeof(*job_rec), NULL);
        if (!data_ptr) {
            aura_iovec_destroy(key_ptr);
            return -1;
        }

        /* Copy over contents for queueing, they will be cleared when their operation completes */
        memcpy(key_ptr->base, buf, key_ptr->len);
        memcpy(data_ptr->base, job_rec, data_ptr->len);
        /* No need for this record anymore */
        aura_free(job_rec);
        res = a_db_enqueue_request(db, A_DB_NS_JOB, A_DB_SCHEMA_JOB_V1, 0, 0, A_DB_FLAG_NONE, A_DB_JOB_OP_STEP, key_ptr, data_ptr, comp);
        if (res != 0) {
            aura_iovec_destroy(key_ptr);
            aura_iovec_destroy(data_ptr);
        }

        return res;
    }
}

struct aura_db_job_rec *aura_db_job_fetch(AURA_DBHANDLE _db, uint64_t job_id, int *error) {
    AURA_DB *db;
    struct aura_db_job_rec *job;
    struct aura_db_rec rec;
    struct aura_iovec key;
    char key_buf[2046];

    db = (AURA_DB *)_db;
    if (job_id) {
        snprintf(key_buf, sizeof(key_buf) - 1, "job:%lu", job_id);
        key.base = key_buf;
        key.len = strlen(key_buf);
        *error = aura_db_record_fetch(_db, A_DB_NS_JOB, A_DB_SCHEMA_JOB_V1, &key, &rec);
        if (!rec.data.base) {
            return NULL;
        }

        return (struct aura_db_job_rec *)rec.data.base;
    }
    return NULL;
}

int aura_db_job_step_insert(AURA_DBHANDLE _db, uint64_t job_id, uint32_t job_type, uint8_t step, struct aura_iovec *target,
                            aura_db_exec_mode exec_mode, struct aura_db_completion *comp) {
    AURA_DB *db;
    struct aura_iovec key, data;
    char job_step_key[2046];
    int res;
    off_t offset;

    /* */
    struct aura_db_job_step_rec job_step = {
      .magic = 0,
      .version = A_DB_VERSION,
      .job_id = job_id,
      .job_type = job_type,
      .step = step,
      .progress = 0,
      .error = 0,
      .updated_at = aura_now_ms(CLOCK_REALTIME),
    };

    /* format: fn_key */
    snprintf(job_step_key, sizeof(job_step_key) - 1, "%s:job:%u", target->base, job_type);

    db = (AURA_DB *)_db;
    if (exec_mode == A_DB_EXEC_DIRECT) {
        key.base = job_step_key;
        key.len = strlen(job_step_key);
        data.base = (void *)&job_step;
        data.len = sizeof(job_step);

        offset = a_db_record_insert_core(_db, A_DB_NS_JOB, A_DB_SCHEMA_JOB_STEP_V1, 0, 0, A_DB_FLAG_NONE, A_DB_JOB_OP_STEP, &key, &data);
        if (offset < 0)
            return -1;
        return 0;
    } else if (exec_mode == A_DB_EXEC_ASYNC) {
        struct aura_iovec *key_ptr, *data_ptr;

        key_ptr = aura_iovec_init(db->mc, strlen(job_step_key), NULL);
        if (!key_ptr)
            return -1;
        data_ptr = aura_iovec_init(db->mc, sizeof(job_step), NULL);
        if (!data_ptr) {
            aura_iovec_destroy(key_ptr);
            return -1;
        }

        /* Copy over contents for queueing */
        memcpy(key_ptr->base, job_step_key, key_ptr->len);
        memcpy(data_ptr->base, &job_step, data_ptr->len);
        res = a_db_enqueue_request(_db, A_DB_NS_JOB, A_DB_SCHEMA_JOB_STEP_V1, 0, 0, A_DB_FLAG_NONE, A_DB_JOB_OP_STEP, key_ptr, data_ptr, comp);
        if (res != 0) {
            aura_iovec_destroy(key_ptr);
            aura_iovec_destroy(data_ptr);
        }

        return res;
    }
}

struct aura_db_job_step_rec *aura_db_job_step_fetch(AURA_DBHANDLE _db, uint16_t job_type, struct aura_iovec *target) {
    struct aura_db_job_step_rec *job_step;
    struct aura_db_rec rec;
    struct aura_iovec key;
    char key_buf[2046];
    int res;

    /* format: fn:fn_name:fn_version:job:<job_type> */
    snprintf(key_buf, sizeof(key_buf), "%s:job:%u", target->base, job_type);
    key.base = key_buf;
    key.len = strlen(key_buf);
    res = aura_db_record_fetch(_db, A_DB_NS_JOB, A_DB_SCHEMA_JOB_STEP_V1, &key, &rec);
    if (!rec.data.base) {
        /* First step was never created: @todo: should create one and return it */
        return NULL;
    }

    return (struct aura_db_job_step_rec *)rec.data.base;
}

static inline int a_db_construct_header(struct aura_db_rec_hdr *rec_hdr, aura_db_namespace namespace, aura_db_schema_id schema_id,
                                        uint64_t old_head, struct aura_iovec *key, struct aura_iovec *data) {
    struct aura_iovec data_checksum;

    data_checksum = aura_calculate_digest(data);
    if (data_checksum.base == NULL && data->base != NULL) {
        app_debug(true, 0, "a_db_construct_header: aura_calculate_digest error");
        return -1;
    }
    rec_hdr->magic = A_DB_REC_MAGIC;
    rec_hdr->version = A_DB_VERSION;
    rec_hdr->ns = namespace;
    rec_hdr->flags = 0;
    rec_hdr->schema_id = schema_id;
    rec_hdr->prev_off = old_head;
    rec_hdr->timestamp = aura_now_ms(CLOCK_REALTIME);
    rec_hdr->rec_len = a_get_db_record_len(key->len, data->len);
    rec_hdr->key_len = key->len;
    rec_hdr->data_len = data->len;
    memcpy(rec_hdr->check_sum, data_checksum.base, DIGEST_LEN);
}

bool aura_db_record_exists(AURA_DBHANDLE _db, uint16_t namespace, uint16_t job_type,
                           uint16_t schema_id, struct aura_iovec *key, bool is_transaction) {
    struct aura_db_job_rec *job_rec;
    struct aura_db_job_step_rec *job_step_rec;
    AURA_DB *db;
    ssize_t res;
    int error;

    db = (AURA_DB *)_db;

    if (is_transaction) {
        /* Fetch latest job step record */
        /* @todo: is this reliable? do all jobs create job steps */
        job_step_rec = aura_db_job_step_fetch(db, job_type, key);
        if (!job_step_rec)
            return false;

        /** @todo: do more sanity checks on the job step */

        /* Get commit canonical job record as confirmation */
        job_rec = aura_db_job_fetch(db, job_step_rec->job_id, &error);
        if (!job_rec) {
            aura_free(job_step_rec);
            return false;
        }

        if (job_rec->state != A_DB_JOB_DONE) {
            aura_free(job_step_rec);
            aura_free(job_rec);
            return false;
        }

        aura_free(job_step_rec);
        aura_free(job_rec);
        return true;
    } else {
        res = aura_db_record_fetch(db, namespace, schema_id, key, NULL);
        if (res == 0)
            return true;

        return false;
    }
}

int aura_db_record_fetch(AURA_DBHANDLE _db, uint16_t namespace, uint16_t schema_id,
                         struct aura_iovec *key, struct aura_db_rec *data_out) {
    struct aura_db_rec_hdr rec_hdr, *hdr;
    uint32_t hash;
    off_t offset;
    ssize_t res;
    char key_buf[2000];
    AURA_DB *db;

    db = (AURA_DB *)_db;
    hash = a_fnv1a_hash(db->db_file_hdr.bucket_cnt, namespace, key);
    offset = db->buckets[hash].head_off;

    if (data_out) {
        memset(data_out, 0, sizeof(*data_out));
    }

    /* Value possible in cache */
    pthread_mutex_lock(&db->db_lock);
    if (offset >= db->curr_file_size) {

        hdr = a_db_record_cache_fetch(db, namespace, schema_id, key, offset, hash);
        if (hdr) {
            if (hdr->flags & A_DB_FLAG_REC_TOMBSTONE) {
                pthread_mutex_unlock(&db->db_lock);
                return A_DB_REC_NOT_FOUND;
            }

            if (data_out) {
                data_out->data.len = hdr->data_len;
                data_out->data.base = aura_alloc(db->mc, data_out->data.len);
                if (!data_out->data.base) {
                    pthread_mutex_unlock(&db->db_lock);
                    goto exception;
                }

                data_out->rec_meta.timestamp = hdr->timestamp;
                memcpy(data_out->rec_meta.check_sum, hdr->check_sum, DIGEST_LEN);

                memcpy(data_out->data.base, (char *)hdr + sizeof(*hdr) + hdr->key_len, hdr->data_len);
                pthread_mutex_unlock(&db->db_lock);
            }

            return 0;
        }
    }
    pthread_mutex_unlock(&db->db_lock);

    if (a_readw_lock(db->db_fd, 0, SEEK_SET, 0) < 0)
        sys_exit(true, errno, "aura_db_record_fetch: a_readw_lock error:");

    while (offset != 0) {
        res = pread(db->db_fd, &rec_hdr, sizeof(rec_hdr), offset);
        if (res < 0)
            goto exception;

        if (rec_hdr.magic != A_DB_REC_MAGIC)
            break;

        memset(key_buf, 0, sizeof(key_buf));
        if (rec_hdr.ns == namespace && rec_hdr.schema_id == schema_id && rec_hdr.key_len == key->len) {
            res = pread(db->db_fd, key_buf, rec_hdr.key_len, offset + sizeof(rec_hdr));
            if (res < 0)
                goto exception;

            if (aura_mem_is_eq(key_buf, strlen(key_buf), key->base, key->len)) {
                if (rec_hdr.flags & A_DB_FLAG_REC_TOMBSTONE)
                    return A_DB_REC_NOT_FOUND;

                if (data_out) {
                    data_out->data.len = rec_hdr.data_len;
                    data_out->data.base = aura_alloc(db->mc, data_out->data.len);
                    if (!data_out->data.base) {
                        goto exception;
                    }

                    res = pread(db->db_fd, data_out->data.base, rec_hdr.data_len, offset + sizeof(rec_hdr) + rec_hdr.key_len);
                    if (res != rec_hdr.data_len) {
                        aura_free(data_out->data.base);
                        goto exception;
                    }

                    data_out->rec_meta.timestamp = rec_hdr.timestamp;
                    memcpy(data_out->rec_meta.check_sum, rec_hdr.check_sum, DIGEST_LEN);

                    res = a_db_record_cache_append(db, &rec_hdr, key, &data_out->data, hash);
                    if (res < 0) {
                        /**/
                    }
                }

                return 0;
            }
        }

        offset = rec_hdr.prev_off;
    }

    if (a_unlock(db->db_fd, 0, SEEK_SET, 0) < 0)
        sys_exit(true, errno, "aura_db_record_fetch: a_unlock error:");

    return A_DB_REC_NOT_FOUND;

exception:
    sys_exit(true, errno, "aura_db_record_fetch error");
}

int aura_db_record_delete(AURA_DBHANDLE _db, uint16_t namespace, uint16_t schema_id, uint64_t job_id,
                          struct aura_iovec *key, aura_db_exec_mode exec_mode, struct aura_db_completion *comp) {
    AURA_DB *db;
    off_t offset;
    int res;

    db = (AURA_DB *)_db;
    if (exec_mode == A_DB_EXEC_DIRECT) {
        offset = a_db_record_insert_core(_db, namespace, schema_id, job_id, 0, A_DB_FLAG_REC_TOMBSTONE, A_DB_OP_DELETE, key, NULL);
        if (offset < 0)
            return -1;
        return 0;
    } else if (exec_mode == A_DB_EXEC_ASYNC) {
        struct aura_iovec *key_ptr;

        key_ptr = aura_iovec_init(db->mc, key->len, NULL);
        if (!key_ptr)
            return -1;

        memcpy(key_ptr->base, key->base, key_ptr->len);
        res = a_db_enqueue_request(_db, namespace, schema_id, job_id, 0, A_DB_FLAG_REC_TOMBSTONE, A_DB_OP_DELETE, key_ptr, NULL, comp);
        if (res < 0) {
            aura_iovec_destroy(key_ptr);
            return -1;
        }
        return 0;
    }
}

/* Append to WAL file */
static inline off_t a_db_wal_append(int wal_fd, struct aura_db_wal_rec_hdr *wal_hdr,
                                    struct aura_db_rec_hdr *rec_hdr, struct aura_iovec *key, struct aura_iovec *data) {
    off_t offset;
    struct iovec iov[5];
    ssize_t res;
    size_t pad_len;

    offset = lseek(wal_fd, 0, SEEK_END);
    if (offset < 0)
        sys_exit(true, errno, "a_db_wal_append: lseek error:");

    /* Update lsn */
    wal_hdr->lsn = offset;

    iov[0].iov_base = wal_hdr;
    iov[0].iov_len = sizeof(*wal_hdr);
    iov[1].iov_base = (void *)rec_hdr;
    iov[1].iov_len = sizeof(*rec_hdr);
    iov[2].iov_base = key->base;
    iov[2].iov_len = key->len;
    iov[3].iov_base = NULL;
    iov[3].iov_len = 0;
    if (data) {
        iov[3].iov_base = data->base;
        iov[3].iov_len = data->len;
    }

    /* Add padding */
    pad_len = rec_hdr->rec_len.aligned_len - rec_hdr->rec_len.raw_len;
    char pad[pad_len];
    memset(pad, 0, pad_len);
    iov[4].iov_base = pad;
    iov[4].iov_len = pad_len;

    res = writev(wal_fd, iov, 5);
    if (res < 0)
        sys_exit(true, errno, "a_db_wal_append: writev error:");

    fsync(wal_fd);
    return offset;
}

/** Write operation to WAL file */
static off_t a_db_wal_commit(int wal_fd, int wal_op, struct aura_db_rec_hdr *rec_hdr,
                             struct aura_iovec *key, struct aura_iovec *data) {
    struct aura_db_wal_rec_hdr wal_hdr;
    off_t offset;

    wal_hdr.magic = A_DB_WAL_MAGIC;
    wal_hdr.op = wal_op;
    wal_hdr.rec_len = rec_hdr->rec_len.aligned_len + sizeof(wal_hdr);

    offset = a_db_wal_append(wal_fd, &wal_hdr, rec_hdr, key, data);
    return offset;
}

/* DB replay structure */
struct aura_db_replay_tab {
    struct {
        uint32_t cnt;
        uint32_t cap;
        struct {
            uint64_t job_id;
            uint32_t state;
        } *visited;
    } jobs;

    struct {
        uint32_t cnt;
        uint32_t cap;
        struct {
            off_t offset;
            uint64_t job_id;
            size_t rec_len;
        } *visited;
    } records;
};

int a_db_replay_tab_add(struct aura_db_replay_tab *tab, uint64_t job_id, uint32_t state, off_t rec_off, size_t rec_len) {

    /* Insert into Job table */
    if (rec_off == 0) {
        /* Check if id is new or updated */
        for (int i = 0; i < tab->jobs.cnt; ++i) {
            if (tab->jobs.visited[i].job_id == job_id) {
                /* Nothing to do */
                if (tab->jobs.visited[i].state == state)
                    return 0;

                /* Otherwise update state */
                tab->jobs.visited[i].state = state;
                return 0;
            }
        }

        if (tab->jobs.cnt >= tab->jobs.cap) {
            tab->jobs.cap = tab->jobs.cap >= 16 ? tab->jobs.cap * 2 : 16;
            tab->jobs.visited = realloc(tab->jobs.visited, tab->jobs.cap * sizeof(tab->jobs.visited));
            if (!tab->jobs.visited)
                return -1;
        }

        tab->jobs.visited[tab->jobs.cnt].job_id = job_id;
        tab->jobs.visited[tab->jobs.cnt].state = state;
        tab->jobs.cnt++;
    } else {
        /* Insert into Record table */
        if (tab->records.cnt >= tab->records.cap) {
            tab->records.cap = tab->records.cap >= 16 ? tab->records.cap * 2 : 16;
            tab->records.visited = realloc(tab->records.visited, tab->records.cap * sizeof(tab->records.visited));
            if (!tab->records.visited)
                return -1;
        }

        tab->records.visited[tab->records.cnt].job_id = job_id;
        tab->records.visited[tab->records.cnt].offset = rec_off;
        tab->records.visited[tab->records.cnt].rec_len = rec_len;
        tab->records.cnt++;
    }

    return 0;
}

static void inline a_db_update_hash_bucket(struct aura_db_rec_hdr *rec_hdr, struct aura_db_bucket_entry *bucket,
                                           uint64_t bucket_cnt, void *key, off_t offset) {
    uint32_t hash;
    struct aura_iovec key_iov;

    key_iov.base = key;
    key_iov.len = rec_hdr->key_len;
    hash = a_fnv1a_hash(bucket_cnt, rec_hdr->ns, &key_iov);
    bucket[hash].head_off = offset;
}

/**
 * Replay operations from WAL file and restore db to
 * achieve consistent state.
 */
static int a_db_wal_replay(AURA_DB *db) {
    struct aura_db_rec_hdr *rec_hdr;
    struct aura_db_hdr hdr;
    struct aura_db_wal_hdr wal_db_hdr;
    struct aura_db_bucket_entry *bucket_buf;
    struct aura_db_replay_tab *replay_tab;
    off_t write_offset;
    ssize_t res;
    struct stat statbuf;
    char *record_buf;
    struct iovec hdr_iov, bucket_iov;
    int rv;
    bool free_new_bucket;

    if (fstat(db->wal_fd, &statbuf) < 0)
        sys_exit(true, errno, "a_db_wal_replay: fstat error:");

    /* wal empty */
    if (statbuf.st_size == sizeof(wal_db_hdr)) {
        return 0;
    }

    pthread_mutex_lock(&db->db_lock);
    db->is_busy = true;
    pthread_mutex_unlock(&db->db_lock);

    bucket_buf = NULL;
    free_new_bucket = true;

    res = pread(db->db_fd, &hdr, sizeof(hdr), 0);
    if (res != sizeof(hdr)) {
        sys_debug(true, errno, "a_db_wal_replay: pread db_hdr error:");
        rv = -1;
        goto out;
    }

    res = pread(db->wal_fd, &wal_db_hdr, sizeof(wal_db_hdr), 0);
    if (res != sizeof(wal_db_hdr)) {
        sys_debug(true, errno, "a_db_wal_replay: pread db_wal_hdr error:");
        rv = -1;
        goto out;
    }

    size_t bucket_size;

    bucket_size = hdr.bucket_cnt * sizeof(struct aura_db_bucket_entry);
    bucket_buf = calloc(1, bucket_size);
    if (!bucket_buf) {
        sys_debug(true, errno, "a_db_wal_replay: bucket buf memory error:");
        rv = -1;
        goto out;
    }

    res = pread(db->db_fd, bucket_buf, bucket_size, hdr.bucket_off);
    if (res != bucket_size) {
        sys_debug(true, errno, "a_db_wal_replay: pread bucket error:");
        rv = -1;
        goto out;
    }

    struct aura_db_wal_rec_hdr wal_rec_hdr;
    size_t record_len, prev_len;
    off_t read_off, prev_off;
    void *key, *data;
    struct aura_iovec c_key, c_data;
    struct aura_db_checkpoint_rec *check_pnt_rec;

    c_key.base = A_DB_CHECK_PNT_RECORD_KEY;
    c_key.len = sizeof(A_DB_CHECK_PNT_RECORD_KEY);

    replay_tab = NULL;
    check_pnt_rec = NULL;
    replay_tab = calloc(1, sizeof(*replay_tab));
    if (!replay_tab) {
        rv = -1;
        goto out;
    }

    struct aura_db_wal_rec_hdr chk_pnt_wal_rec_hdr;
    struct aura_db_rec_hdr *chk_pnt_rec_hdr;
    ssize_t rc;
    size_t chk_pnt_rec_data_len;
    void *ch_pnt_data;

    /* Read in checkpoint record stored at offset hdr.lsn */
    ch_pnt_data = NULL;
    if (hdr.lsn > 0) {
        rc = pread(db->wal_fd, &chk_pnt_wal_rec_hdr, sizeof(chk_pnt_wal_rec_hdr), hdr.lsn);
        if (rc != sizeof(chk_pnt_wal_rec_hdr)) {
            rv = -1;
            goto out;
        }

        a_db_dump_wal_header(&chk_pnt_wal_rec_hdr);

        chk_pnt_rec_data_len = chk_pnt_wal_rec_hdr.rec_len - sizeof(chk_pnt_wal_rec_hdr);
        ch_pnt_data = malloc(chk_pnt_rec_data_len);
        if (!ch_pnt_data) {
            rv = -1;
            goto out;
        }

        rc = pread(db->wal_fd, ch_pnt_data, chk_pnt_rec_data_len, hdr.lsn + sizeof(chk_pnt_wal_rec_hdr));
        if (rc != chk_pnt_rec_data_len) {
            rv = -1;
            goto out;
        }

        struct aura_db_rec_hdr *ch_pnt_data_hdr;
        ch_pnt_data_hdr = (struct aura_db_rec_hdr *)ch_pnt_data;

        check_pnt_rec = (struct aura_db_checkpoint_rec *)((char *)ch_pnt_data +
                                                          sizeof(*ch_pnt_data_hdr) + ch_pnt_data_hdr->key_len);
        check_pnt_rec->pending_jobs = (struct aura_db_pending_job *)((char *)check_pnt_rec + sizeof(*check_pnt_rec));
        check_pnt_rec->pending_job_records = (struct aura_db_pending_job_rec *)((char *)check_pnt_rec->pending_jobs +
                                                                                (sizeof(struct aura_db_pending_job) * check_pnt_rec->pending_job_rec_cnt));

        for (int i = 0; i < check_pnt_rec->pending_job_cnt; ++i) {
            if (a_db_replay_tab_add(replay_tab, check_pnt_rec->pending_jobs[i].job_id,
                                    check_pnt_rec->pending_jobs[i].job_state, 0, 0) != 0) {
                goto out;
            }
        }

        for (int i = 0; i < check_pnt_rec->pending_job_rec_cnt; ++i) {
            if (a_db_replay_tab_add(replay_tab, check_pnt_rec->pending_job_records[i].job_id, 0,
                                    check_pnt_rec->pending_job_records[i].rec_off,
                                    check_pnt_rec->pending_job_records[i].rec_len) != 0) {
                goto out;
            }
        }
    }

    prev_len = 4096;
    record_buf = calloc(1, prev_len);
    if (!record_buf)
        return -1;

    read_off = hdr.lsn == 0 ? sizeof(wal_db_hdr) : hdr.lsn + chk_pnt_wal_rec_hdr.rec_len;
    /* No new records were added */
    if (read_off == statbuf.st_size) {
        rv = 0;
        goto out;
    }

    prev_off = db->db_file_hdr.last_rec_off;

    while (true) {
        res = pread(db->wal_fd, &wal_rec_hdr, sizeof(wal_rec_hdr), read_off);
        /* EOF */
        if (res == 0) {
            // __atomic_store_n(&db->is_busy, false, __ATOMIC_RELEASE);

            uint32_t state, chk_pnt_data_len;
            uint64_t job_id;
            struct aura_db_checkpoint_rec *chk_pnt_rec;
            struct aura_db_replay_tab *chk_pnt_tab;
            struct aura_iovec chk_pnt_key, chk_pnt_data;
            struct aura_db_wal_rec_hdr chk_pnt_wal_rec_hdr;
            struct aura_db_rec_hdr chk_pnt_rec_hdr;
            off_t chk_pnt_off;
            size_t pending_job_cnt, pending_job_rec_cnt;
            int res;

            pending_job_cnt = 0;
            pending_job_rec_cnt = 0;
            for (int i = 0; i < replay_tab->jobs.cnt; ++i) {
                state = replay_tab->jobs.visited[i].state;
                if (state != A_DB_JOB_DONE && state != A_DB_JOB_FAILED) {
                    pending_job_cnt++;

                    for (int j = 0; j < replay_tab->records.cnt; ++j) {
                        if (replay_tab->records.visited[j].job_id == replay_tab->jobs.visited[i].job_id) {
                            pending_job_rec_cnt++;
                        }
                    }
                }
            }

            chk_pnt_data_len = sizeof(*chk_pnt_rec) +
                               sizeof(struct aura_db_pending_job) * pending_job_cnt +
                               sizeof(struct aura_db_pending_job_rec) * pending_job_rec_cnt;

            chk_pnt_key.base = A_DB_CHECK_PNT_RECORD_KEY;
            chk_pnt_key.len = sizeof(A_DB_CHECK_PNT_RECORD_KEY) - 1;
            chk_pnt_data.base = calloc(1, chk_pnt_data_len);
            chk_pnt_data.len = chk_pnt_data_len;

            chk_pnt_rec = (struct aura_db_checkpoint_rec *)chk_pnt_data.base;
            chk_pnt_rec->version = A_DB_VERSION;
            chk_pnt_rec->magic = A_DB_CHK_PNT_MAGIC;
            chk_pnt_rec->lsn = hdr.lsn;
            chk_pnt_rec->pending_job_cnt = pending_job_cnt;
            chk_pnt_rec->pending_job_rec_cnt = pending_job_rec_cnt;
            chk_pnt_rec->pending_jobs = (struct aura_db_pending_job *)(chk_pnt_data.base + sizeof(*chk_pnt_rec));
            chk_pnt_rec->pending_job_records = (struct aura_db_pending_job_rec *)((char *)chk_pnt_rec->pending_jobs + (sizeof(struct aura_db_pending_job) * pending_job_cnt));

            /* Store pending jobs */
            int rec_idx = 0;
            for (int i = 0, job_idx = 0; i < replay_tab->jobs.cnt, job_idx < pending_job_cnt; ++i) {
                state = replay_tab->jobs.visited[i].state;
                job_id = replay_tab->jobs.visited[i].job_id;
                if (state != A_DB_JOB_DONE && state != A_DB_JOB_FAILED) {
                    chk_pnt_rec->pending_jobs[job_idx].job_id = job_id;
                    chk_pnt_rec->pending_jobs[job_idx].job_state = state;
                    // chk_pnt_rec->pending_jobs[job_idx].job_type = replay_tab->jobs.visited[i].type;
                    // chk_pnt_rec->pending_jobs[job_idx].last_committed_lsn = replay_tab->jobs.visited[i].last_committed_lsn;
                    job_idx++;

                    /**
                     * For each job, check records table for associated records
                     */
                    for (int k = 0; k < replay_tab->records.cnt; ++k) {
                        if (replay_tab->records.visited[k].job_id == job_id) {
                            chk_pnt_rec->pending_job_records[rec_idx].job_id = job_id;
                            chk_pnt_rec->pending_job_records[rec_idx].rec_len = replay_tab->records.visited[k].rec_len;
                            chk_pnt_rec->pending_job_records[rec_idx].rec_off = replay_tab->records.visited[k].offset;
                            rec_idx++;
                        }
                    }
                }
            }

            res = a_db_record_header_init(db, &chk_pnt_rec_hdr, A_DB_NS_CHECK_PNT,
                                          A_DB_SCHEMA_CHECK_PNT, A_DB_JOB_ID_NONE, A_DB_PREV_JOB_REC_NONE,
                                          &chk_pnt_key, &chk_pnt_data, 0);
            if (res < 0) {
                free(chk_pnt_data.base);
                goto out;
            }

            chk_pnt_wal_rec_hdr.magic = A_DB_WAL_MAGIC;
            chk_pnt_wal_rec_hdr.op = A_DB_OP_INSERT;
            chk_pnt_wal_rec_hdr.rec_len = chk_pnt_rec_hdr.rec_len.aligned_len + sizeof(chk_pnt_wal_rec_hdr);

            chk_pnt_off = a_db_wal_append(db->wal_fd, &chk_pnt_wal_rec_hdr, &chk_pnt_rec_hdr, &chk_pnt_key, &chk_pnt_data);
            if (chk_pnt_off < 0) {
                free(chk_pnt_data.base);
                rv = -1;
                goto out;
            }

            hdr.lsn = chk_pnt_off;
            hdr_iov.iov_base = &hdr;
            hdr_iov.iov_len = sizeof(hdr);
            bucket_iov.iov_base = bucket_buf;
            bucket_iov.iov_len = bucket_size;

            res = a_db_meta_write(db->db_fd, &hdr_iov, &bucket_iov);
            if (res != (hdr_iov.iov_len + bucket_iov.iov_len)) {
                sys_debug(true, errno, "a_db_wal_replay: a_db_meta_write error:");
                free(chk_pnt_data.base);
                rv = -1;
                goto out;
            }

            wal_db_hdr.last_replay_ts = aura_now_ms(CLOCK_REALTIME);

            hdr_iov.iov_base = &wal_db_hdr;
            hdr_iov.iov_len = sizeof(wal_db_hdr);
            bucket_iov.iov_base = NULL;
            bucket_iov.iov_len = 0;

            res = a_db_meta_write(db->wal_fd, &hdr_iov, &bucket_iov);
            if (res != (hdr_iov.iov_len)) {
                sys_debug(true, errno, "a_db_wal_replay: a_db_meta_write error:");
                free(chk_pnt_data.base);
                rv = -1;
                goto out;
            }

            fsync(db->db_fd);

            /* Sync in memory hash */
            struct aura_db_bucket_entry *old_bucket;
            pthread_mutex_lock(&db->db_lock);
            memcpy(&db->db_file_hdr, &hdr, sizeof(hdr));
            memcpy(&db->wal_file_hdr, &wal_db_hdr, sizeof(wal_db_hdr));
            old_bucket = db->buckets;
            db->buckets = bucket_buf;
            pthread_mutex_unlock(&db->db_lock);
            free(old_bucket);
            free_new_bucket = false;
            rv = 0;
            free(chk_pnt_data.base);
            goto out;
        }

        if (res != sizeof(wal_rec_hdr)) {
            rv = -1;
            goto out;
        }

        if (wal_rec_hdr.magic != A_DB_WAL_MAGIC) {
            rv = -1;
            goto out;
        }

        /* Skip already replayed */
        if (wal_rec_hdr.lsn <= hdr.lsn) {
            read_off += wal_rec_hdr.rec_len;
            continue;
        }

        /* Replay this */
        record_len = wal_rec_hdr.rec_len - sizeof(wal_rec_hdr);
        /**
         * Allocate only if more memory is needed
         */
        if (prev_len < record_len) {
            record_buf = realloc(record_buf, record_len);
            prev_len = record_len;
        } else {
            memset(record_buf, 0, prev_len);
        }

        if (!record_buf) {
            rv = -1;
            goto out;
        }

        res = pread(db->wal_fd, record_buf, record_len, read_off + sizeof(wal_rec_hdr));
        if (res != record_len) {
            rv = -1;
            goto out;
        }

        void *key, *data;

        rec_hdr = (struct aura_db_rec_hdr *)record_buf;

        /* Update record chain in bucket */
        rec_hdr->prev_off = prev_off;
        key = (void *)((char *)rec_hdr + sizeof(*rec_hdr));

        switch (wal_rec_hdr.op) {
        case A_DB_OP_INSERT:
        case A_DB_OP_DELETE:
            if (rec_hdr->magic != A_DB_REC_MAGIC) {
                rv = -1;
                goto out;
            }

            data = (void *)((char *)key + rec_hdr->key_len);
            /**
             * Not part of any job scope atomic group
             * Append immediately to db
             */
            if (rec_hdr->job_id == 0) {
                rec_hdr->prev_off = prev_off;
                write_offset = a_db_record_append(db->db_fd, rec_hdr, key, data, 0);
                prev_off = write_offset;
                hdr.lsn = wal_rec_hdr.lsn;
                break;
            }

            /**
             * part of job scope atomic group
             * Append record to record table
             */
            if (rec_hdr->job_id > 0) {
                a_db_replay_tab_add(replay_tab, rec_hdr->job_id, 0, read_off + sizeof(wal_rec_hdr), rec_hdr->rec_len.aligned_len);
            }

            break;

        case A_DB_JOB_OP_CREATE:
        case A_DB_JOB_OP_STEP:
            struct aura_db_job_rec *job_rec;

            if (rec_hdr->magic != A_DB_REC_MAGIC) {
                rv = -1;
                goto out;
            }

            data = (void *)((char *)key + rec_hdr->key_len);
            job_rec = (struct aura_db_job_rec *)data;
            if (a_db_replay_tab_add(replay_tab, job_rec->job_id, job_rec->state, 0, 0) != 0) {
                rv = -1;
                goto out;
            }

            if (job_rec->state == A_DB_JOB_DONE) {
                uint64_t _record_len, _prev_len;
                struct aura_db_rec_hdr *_rec_hdr;
                void *key_ptr, *_data_ptr;
                off_t _write_off;

                _prev_len = 4096;
                _data_ptr = calloc(1, _prev_len);

                /**
                 * Loop and append all records for this job
                 * in forward manner
                 */
                for (int i = 0; i < replay_tab->records.cnt; ++i) {
                    if (replay_tab->records.visited[i].job_id == job_rec->job_id) {
                        _record_len = replay_tab->records.visited[i].rec_len;

                        if (_prev_len < _record_len) {
                            _data_ptr = realloc(_data_ptr, _record_len);
                            _prev_len = _record_len;
                        } else {
                            memset(_data_ptr, 0, _prev_len);
                        }

                        if (!_data_ptr) {
                            rv = -1;
                            goto out;
                        }

                        res = pread(db->wal_fd, _data_ptr, _record_len, replay_tab->records.visited[i].offset);
                        if (res != _record_len) {
                            free(_data_ptr);
                            rv = -1;
                            goto out;
                        }

                        /**
                         * We can safely update the prev_off
                         * as we are just appending!
                         */
                        _rec_hdr = (struct aura_db_rec_hdr *)_data_ptr;
                        _rec_hdr->prev_off = prev_off;
                        key_ptr = (char *)_rec_hdr + sizeof(*_rec_hdr);
                        _write_off = a_db_record_append(db->db_fd, _rec_hdr, key_ptr, (char *)key_ptr + _rec_hdr->key_len, 0);
                        if (_write_off < 0) {
                            rv = -1;
                            goto out;
                        }
                        prev_off = _write_off;

                        a_db_update_hash_bucket(_rec_hdr, bucket_buf, hdr.bucket_cnt, key_ptr, _write_off);
                    }
                }
                if (_data_ptr)
                    free(_data_ptr);
            }

            /* append job record */
            write_offset = a_db_record_append(db->db_fd, rec_hdr, key, data, 0);
            prev_off = write_offset;
            hdr.lsn = wal_rec_hdr.lsn;
            break;

        default:
            break;
        }

        if (write_offset == -1) {
            sys_debug(true, errno, "a_db_wal_replay: a_db_record_append error:");
            rv = -1;
            goto out;
        }

        hdr.last_rec_off = write_offset;
        hdr.file_size += rec_hdr->rec_len.aligned_len;

        a_db_update_hash_bucket(rec_hdr, bucket_buf, hdr.bucket_cnt, key, write_offset);

        read_off += wal_rec_hdr.rec_len;
    }

out:
    __atomic_store_n(&db->is_busy, false, __ATOMIC_RELEASE);

    if (free_new_bucket)
        free(bucket_buf);

    if (record_buf)
        free(record_buf);

    if (replay_tab) {
        if (replay_tab->jobs.visited)
            free(replay_tab->jobs.visited);

        if (replay_tab->records.visited)
            free(replay_tab->records.visited);

        free(replay_tab);
    }

    if (ch_pnt_data)
        free(ch_pnt_data);

    return rv;
}

/* Compaction table structure */
struct aura_db_compact_table {
    char *key_buf;
    void *record_buf;
    size_t record_buf_size;
    size_t key_off;
    uint32_t cnt;
    size_t cap;
};

static inline void a_db_compact_table_append(struct aura_db_compact_table *comp_tab,
                                             struct aura_db_rec_hdr *hdr, const char *key) {
    size_t comp_tab_entry_len;

    if ((comp_tab->key_off + sizeof(size_t) + hdr->key_len) >= comp_tab->cap) {
        comp_tab->cap *= 2;
        comp_tab->key_buf = realloc(comp_tab->key_buf, comp_tab->cap);
        if (!comp_tab->key_buf)
            sys_exit(true, errno, "a_db_compact_table_append: realloc error:");
    }

    comp_tab_entry_len = sizeof(size_t) + hdr->key_len; /* key_len + key_string */
    snprintf(comp_tab->key_buf + comp_tab->key_off, sizeof(size_t) + 1, "%u", hdr->key_len);
    snprintf(comp_tab->key_buf + comp_tab->key_off + sizeof(size_t), hdr->key_len + 1, "%s", key);

    comp_tab->key_off += comp_tab_entry_len;
    comp_tab->cnt++;
}

/**
 * Compact database and prune deleted records
 */
static int a_db_compact(AURA_DB *db) {
    struct aura_db_rec_hdr rec_hdr;
    struct aura_db_compact_table comp_tab;
    struct aura_iovec key;
    struct aura_db_bucket_entry *new_hash_table;
    struct aura_db_hdr new_hdr;
    size_t comp_tab_entry_len, key_len, new_file_size, bucket_arr_size;
    char key_buf[4096], *data_buf;
    off_t read_off, write_off, old_off;
    bool record_deleted;
    ssize_t res;
    int new_fd;

    comp_tab.key_buf = malloc(65536); /* 64KB */
    comp_tab.cnt = comp_tab.key_off = 0;
    comp_tab.cap = 65536;
    read_off = db->db_file_hdr.record_off;

    old_off = 0;
    data_buf = NULL;
    bucket_arr_size = sizeof(struct aura_db_bucket_entry) * A_DB_BUCKET_CNT;
    new_file_size = sizeof(struct aura_db_hdr) + bucket_arr_size;

    /* Construct compact_file_path */
    char compact_file_path[256], *ptr;
    size_t len;
    ptr = strrchr(db->name, '/');
    len = ptr - db->name + 2;
    snprintf(compact_file_path, len, "%s", db->name);
    strcat(compact_file_path, AURA_DB_COMPACT_FILE);
    new_fd = open(compact_file_path, O_RDWR | O_CREAT | O_TRUNC, S_IRWXU, A_DB_FILE_MODE);
    if (new_fd < 0) {
        free(comp_tab.key_buf);
        return -1;
    }

    /* Initialize new hash table */
    new_hash_table = malloc(db->db_file_hdr.bucket_cnt * sizeof(struct aura_db_bucket_entry));
    if (!new_hash_table) {
        free(comp_tab.key_buf);
        close(new_fd);
        return -1;
    }

    uint64_t new_record_cnt;
    new_record_cnt = 0;
    write_off = 0;
    /* Loop for each hash table bucket */
    for (int i = 0; i < db->db_file_hdr.bucket_cnt; ++i) {
        read_off = db->buckets[i].head_off;

        while (read_off > 0) {
            res = pread(db->db_fd, &rec_hdr, sizeof(rec_hdr), read_off);
            if (res != sizeof(rec_hdr))
                goto err_out_fd;

            res = pread(db->db_fd, key_buf, rec_hdr.key_len, read_off + sizeof(rec_hdr));
            if (res != rec_hdr.key_len)
                goto err_out_fd;

            if (rec_hdr.flags & A_DB_FLAG_REC_TOMBSTONE) {
                /* Append deleted record in compaction table */
                a_db_compact_table_append(&comp_tab, &rec_hdr, key_buf);
                read_off = rec_hdr.prev_off;
                continue;
            }

            /* Search compaction table if this record was deleted */
            record_deleted = false;
            for (int i = 0, key_off = 0; i < comp_tab.cnt; ++i) {
                aura_scan_str(comp_tab.key_buf + key_off, "%lu", &key_len);
                if (aura_mem_is_eq(key_buf, rec_hdr.key_len, comp_tab.key_buf + key_off + sizeof(size_t), key_len)) {
                    record_deleted = true;
                    break;
                }
                key_off += sizeof(size_t) + key_len;
            }

            if (record_deleted) {
                /* Skip */
                read_off = rec_hdr.prev_off;
                continue;
            } else {
                /* Append to new db file */
                data_buf = realloc(data_buf, rec_hdr.data_len);
                if (!data_buf)
                    goto err_out_fd;

                res = pread(db->db_fd, data_buf, rec_hdr.data_len, read_off + sizeof(rec_hdr) + rec_hdr.key_len);
                if (res != rec_hdr.data_len) {
                    free(data_buf);
                    goto err_out_fd;
                }

                uint32_t hash;
                key.base = key_buf;
                key.len = rec_hdr.key_len;
                hash = a_fnv1a_hash(db->db_file_hdr.bucket_cnt, rec_hdr.ns, &key);

                write_off = a_db_record_append(
                  new_fd, &rec_hdr,
                  (void *)key_buf,
                  (void *)data_buf,
                  write_off < db->db_file_hdr.record_off ? db->db_file_hdr.record_off : write_off);

                if (write_off < 0) {
                    free(data_buf);
                    goto err_out_fd;
                }

                new_hash_table[hash].head_off = write_off;
                read_off = rec_hdr.prev_off;
                /* update records offsets for this new db file */
                rec_hdr.prev_off = old_off;
                old_off = write_off;
                new_file_size += rec_hdr.rec_len.aligned_len;
                new_record_cnt++;
            }
        }
    }

    // memcpy(&new_hdr, &db->db_hdr, sizeof(new_hdr));
    pthread_mutex_lock(&db->db_lock);
    db->db_file_hdr.file_size = new_file_size;
    db->db_file_hdr.last_compact_ts = aura_now_ms(CLOCK_REALTIME);
    db->db_file_hdr.record_cnt = new_record_cnt;
    memcpy(&new_hdr, &db->db_file_hdr, sizeof(new_hdr));
    pthread_mutex_unlock(&db->db_lock);

    struct iovec hdr_iov, bucket_iov;
    struct aura_db_bucket_entry *old_hash_table;
    int old_fd;

    /* Write new db meta */
    if (lseek(new_fd, 0, SEEK_SET) < 0)
        sys_exit(true, errno, "a_db_compact: lseek");

    hdr_iov.iov_base = &new_hdr;
    hdr_iov.iov_len = sizeof(struct aura_db_hdr);
    bucket_iov.iov_base = new_hash_table;
    bucket_iov.iov_len = db->db_file_hdr.bucket_cnt * sizeof(struct aura_db_bucket_entry);

    if (a_db_meta_write(new_fd, &hdr_iov, &bucket_iov) < 0)
        goto err_out_fd;
    fsync(new_fd);

    pthread_mutex_lock(&db->db_lock);
    old_fd = db->db_fd;
    old_hash_table = db->buckets;
    db->db_fd = new_fd;
    db->buckets = new_hash_table;
    /* Reset the cache for now */
    memset(db->record_buf, 0, db->record_buf_size);
    pthread_mutex_unlock(&db->db_lock);

    /* Remove new file and rename old file */
    free(old_hash_table);
    close(old_fd);
    unlink(db->name);
    res = rename(compact_file_path, db->name);

    free(comp_tab.key_buf);
    free(data_buf);
    return 0;

err_out_fd:
    free(comp_tab.key_buf);
    free(new_hash_table);
    close(new_fd);
    return -1;
}

static void *a_db_writer_routine(void *arg) {
    AURA_DB *db;
    struct aura_db_write_req *req;
    struct timespec ts;
    bool timed_out;
    uint64_t time_waited;
    int res;
    ssize_t rv;

    db = arg;

    for (;;) {
        pthread_mutex_lock(&db->writer_queue.mutex);
        aura_now_ts(&ts, CLOCK_REALTIME);
        ts.tv_sec += 30 * 60;
        timed_out = false;
        time_waited = 0;

        while (a_list_is_empty(&db->writer_queue.db_list)) {
            res = pthread_cond_timedwait(&db->writer_queue.cond, &db->writer_queue.mutex, &ts);

            if (res == 0) {
                /* Normal break out, accumulate the time waited */
                time_waited += (ts.tv_sec * 1000) - ((ts.tv_sec * 1000) - aura_now_ms(CLOCK_REALTIME));
                break;
            } else if (res == ETIMEDOUT) {
                timed_out = true;
                break;
            } else {
                /* Error */
                pthread_mutex_unlock(&db->writer_queue.mutex);
                return NULL;
            }
        }

        /**
         * Stop the process from queing anything else for now
         * @todo: may not need this afterall
         */
        if (timed_out) {
            db->is_busy = true;
        }

        a_list_dequeue(req, &db->writer_queue.db_list, w_list);
        pthread_mutex_unlock(&db->writer_queue.mutex);

        if (req) {
            switch (req->op) {
            case A_DB_OP_INSERT:
            case A_DB_JOB_OP_CREATE:
            case A_DB_JOB_OP_STEP:
                rv = a_db_record_insert_core((void *)db, req->namespace, req->schema_id, req->job_id, req->prev_job_rec, req->flags, req->op, req->key, req->data);
                aura_iovec_destroy(req->key);
                aura_iovec_destroy(req->data);
                break;

            case A_DB_OP_DELETE:
                rv = a_db_record_insert_core((void *)db, req->namespace, req->schema_id, req->job_id, req->prev_job_rec, req->flags, req->op, req->key, req->data);
                aura_iovec_destroy(req->key);
                break;
            default:
                break;
            }

            if (req->completion) {
                if (req->completion->on_complete) {
                    req->completion->on_complete(req->completion, rv);
                }
            }
        }

        if (timed_out) {
            res = a_db_wal_replay(db);
        }

        if (db->shutdown)
            break;
    }
}

/* Create the timer and thread handles compaction */
int aura_db_start_bg_tasks(AURA_DBHANDLE _db) {
    AURA_DB *db;
    pthread_t compact_thread_id;
    pthread_attr_t thread_attr;
    int err;

    db = (AURA_DB *)_db;
    err = pthread_attr_init(&thread_attr);
    if (err != 0)
        sys_exit(true, 0, "aura_db_start_bg_tasks: pthread_attr_init error: %d", err);

    err = pthread_attr_setdetachstate(&thread_attr, PTHREAD_CREATE_DETACHED);
    if (err != 0)
        sys_exit(true, 0, "aura_db_start_bg_tasks: pthread_attr_setdetachstate error: %d", err);

    err = pthread_create(&compact_thread_id, &thread_attr, a_db_writer_routine, (void *)db);
    if (err != 0)
        sys_exit(true, 0, "aura_db_start_bg_tasks: pthread_create error: %d", err);

    return 0;
}

int aura_db_record_for_each(AURA_DBHANDLE _db, uint64_t record_cnt, uint16_t namespace,
                            uint16_t schema_id, int (*fn)(struct iovec)) {
    AURA_DB *db;
    struct aura_db_rec_hdr rec_hdr;
    uint64_t cnt, curr_record_cnt, file_size;
    off_t offset;
    ssize_t res;
    int rv;

    db = (AURA_DB *)_db;
    a_db_dump_header(&db->db_file_hdr);
    pthread_mutex_lock(&db->db_lock);
    curr_record_cnt = db->db_file_hdr.record_cnt;
    file_size = db->curr_file_size;
    offset = db->db_file_hdr.record_off;
    pthread_mutex_unlock(&db->db_lock);
    cnt = a_min(record_cnt, curr_record_cnt);

    while (offset < file_size && cnt-- > 0) {
        res = pread(db->db_fd, &rec_hdr, sizeof(rec_hdr), offset);
        if (res != sizeof(rec_hdr))
            sys_exit(true, errno, "aura_db_loop_record: pread error:");

        if (rec_hdr.ns == namespace && rec_hdr.schema_id == schema_id) {
            if (rec_hdr.data_len == 0)
                rv = fn((struct iovec){.iov_base = NULL, .iov_len = 0});
            else {
                void *data;
                data = calloc(1, rec_hdr.data_len);
                if (!data)
                    sys_exit(true, errno, "aura_db_loop_record: memory error:");

                res = pread(db->db_fd, data, rec_hdr.data_len, offset + sizeof(rec_hdr) + rec_hdr.key_len);
                if (res != rec_hdr.data_len)
                    sys_exit(true, errno, "aura_db_loop_record: pread error:");

                rv = fn((struct iovec){.iov_base = data, .iov_len = rec_hdr.data_len});
            }

            if (rv != 0)
                return rv;
        }
        offset += rec_hdr.rec_len.aligned_len;
    }

    return 0;
}

/* used in testing to manually trigger replay */
int aura_db_force_wal_replay(AURA_DBHANDLE _db) {
    AURA_DB *db;

    db = (AURA_DB *)_db;
    a_db_wal_replay(db);
    return 0;
}
/* used in testing to manually trigger compaction */
int aura_db_force_compact(AURA_DBHANDLE db) {
    a_db_compact(db);
    return 0;
}

/* Clear in memory cache */
int aura_db_clear_record_cache(AURA_DBHANDLE _db) {
    AURA_DB *db;

    db = (AURA_DB *)_db;
    pthread_mutex_lock(&db->db_lock);
    memset(db->record_buf, 0, db->record_buf_size);
    pthread_mutex_unlock(&db->db_lock);

    return 0;
}

/**/
size_t aura_db_get_size(AURA_DBHANDLE _db) {
    AURA_DB *db;

    db = (AURA_DB *)_db;
    return __atomic_load_n(&db->db_file_hdr.file_size, __ATOMIC_ACQUIRE);
}

uint64_t aura_db_get_record_cnt(AURA_DBHANDLE _db) {
    AURA_DB *db;

    db = (AURA_DB *)_db;
    uint64_t record_cnt;
    record_cnt = __atomic_load_n(&db->db_file_hdr.record_cnt, __ATOMIC_ACQUIRE);
    return record_cnt;
}

/**
 * Print database header
 */
static void a_db_dump_header(struct aura_db_hdr *hdr) {
    app_debug(true, 0, "AURA DB HEADER");
    app_debug(true, 0, "    Magic: %x", hdr->magic);
    app_debug(true, 0, "    Version: %u", hdr->version);
    app_debug(true, 0, "    Flags: %u", hdr->flags);
    app_debug(true, 0, "    Created at: %u", hdr->created_ts);
    app_debug(true, 0, "    Hash algorithm: %u", hdr->hash_algo);
    app_debug(true, 0, "    Bucket off: %u", hdr->bucket_off);
    app_debug(true, 0, "    Bucket count: %u", hdr->bucket_cnt);
    app_debug(true, 0, "    File size: %u", hdr->file_size);
    app_debug(true, 0, "    Record count: %u", hdr->record_cnt);
    app_debug(true, 0, "    Last compaction at: %u", hdr->last_compact_ts);
}

/* Map namepace Id to string rep */
char *a_db_get_namespace_str(uint16_t ns) {
    switch (ns) {
    case A_DB_NS_FN:
        return "Function NS";
    case A_DB_NS_JOB:
        return "Job NS";
    case A_DB_NS_CHECK_PNT:
        return "Check point NS";
    default:
        return "Unknown namespace";
    }
}

/* Map schema Id to string rep */
char *a_db_get_schema_str(uint16_t schema_id) {
    switch (schema_id) {
    case A_DB_SCHEMA_FN_CODE_V1:
        return "Schema Code Bytes";
    case A_DB_SCHEMA_FN_CONFIG_V1:
        return "Schema Function Config";
    case A_DB_SCHEMA_FN_META_V1:
        return "Schema Function Meta";
    case A_DB_SCHEMA_FN_STAT_DELTA:
        return "Schema Stat Delta";
    case A_DB_SCHEMA_JOB_V1:
        return "Schema Job";
    case A_DB_SCHEMA_JOB_STEP_V1:
        return "Schema Job step";
    case A_DB_SCHEMA_FN_PETITE_V1:
        return "Schema Fn Petite";
    case A_DB_SCHEMA_FNS:
        return "Schema Function List";
    default:
        return "Schema Unknown";
    }
}

/* Print single db record header */
static void a_db_dump_rec_header(struct aura_db_rec_hdr *hdr) {
    app_debug(true, 0, "AURA DB RECORD HEADER");
    app_debug(true, 0, "    Magic: %x", hdr->magic);
    app_debug(true, 0, "    Version: %u", hdr->version);
    app_debug(true, 0, "    Namespace: %u: %s", hdr->ns, a_db_get_namespace_str(hdr->ns));
    app_debug(true, 0, "    Schema Id: %u: %s", hdr->schema_id, a_db_get_schema_str(hdr->schema_id));
    app_debug(true, 0, "    Job Id: %lu", hdr->job_id);
    app_debug(true, 0, "    Prev Job Rec off: %ld", hdr->prev_job_rec);
    app_debug(true, 0, "    Flags: %u", hdr->flags);
    app_debug(true, 0, "    Key len: %u", hdr->key_len);
    app_debug(true, 0, "    Data len: %u", hdr->data_len);
    app_debug(true, 0, "    Record len: %u", hdr->rec_len.aligned_len);
    app_debug(true, 0, "    Previous offset: %u", hdr->prev_off);
    app_debug(true, 0, "    Timestamp: %u", hdr->timestamp);
}

static char *a_db_get_op(uint16_t op) {
    switch (op) {
    case A_DB_OP_INSERT:
        return "OP Insert";
    case A_DB_OP_DELETE:
        return "OP Delete";
    case A_DB_JOB_OP_CREATE:
        return "OP Job create";
    case A_DB_JOB_OP_STEP:
        return "OP Job Step";
    default:
        return "Unknown OP";
    }
}

/* Print single WAL record header */
static void a_db_dump_wal_header(struct aura_db_wal_rec_hdr *hdr) {
    app_debug(true, 0, "AURA DB WAL RECORD HEADER");
    app_debug(true, 0, "    Magic: %x", hdr->magic);
    app_debug(true, 0, "    Op: %u: %s", hdr->op, a_db_get_op(hdr->op));
    app_debug(true, 0, "    Record len: %lu", hdr->rec_len);
}

static char *a_db_job_get_state_str(uint16_t state) {
    switch (state) {
    case A_DB_JOB_START:
        return "START";
    case A_DB_JOB_DONE:
        return "DONE";
    case A_DB_JOB_RUNNING:
        return "RUNNING";
    case A_DB_JOB_FAILED:
        return "FAILED";
    default:
        return "Unknown";
    }
}

/* Print job structure */
static void a_db_job_dump(struct aura_db_job_rec *job) {
    app_debug(true, 0, "AURA DB JOB");
    app_debug(true, 0, "    Magic: %x", job->magic);
    app_debug(true, 0, "    Version: %u", job->version);
    app_debug(true, 0, "    ID: %lu", job->job_id);
    app_debug(true, 0, "    Type: %u", job->job_type);
    app_debug(true, 0, "    State: %s", a_db_job_get_state_str(job->state));
    // app_debug(true, 0, "    Target: %s", job->target);
    app_debug(true, 0, "    Error code: %u", job->error_code);
    // app_debug(true, 0, "    Progress: %u", job->progress);
    app_debug(true, 0, "    Created at: %lu", job->created_at);
    // app_debug(true, 0, "    Updated at: %lu", job->updated_at);
    app_debug(true, 0, "    Expires at: %lu", job->ttl_epoch);
}

/* Print A check record */
static void a_db_check_pnt_rec_dump(struct aura_db_checkpoint_rec *rec) {
    app_debug(true, 0, "AURA DB CHECK RECORD");
    app_debug(true, 0, "    Version: %u", rec->version);
    app_debug(true, 0, "    Magic: %u", rec->magic);
    app_debug(true, 0, "    LSN: %lu", rec->lsn);
    app_debug(true, 0, "    Pending jobs: %lu", rec->pending_job_cnt);
    app_debug(true, 0, "    Pending job recs: %lu", rec->pending_job_rec_cnt);

    for (int i = 0; i < rec->pending_job_cnt; ++i) {
        app_debug(true, 0, "    Job");
        app_debug(true, 0, "        Job Id: %lu", rec->pending_jobs[i].job_id);
        app_debug(true, 0, "        Job state: %u: %s", rec->pending_jobs[i].job_state, a_db_job_get_state_str(rec->pending_jobs[i].job_state));
        app_debug(true, 0, "        Job Type: %u", rec->pending_jobs[i].job_type);
        // app_debug(true, 0, "        Job Id", rec->pending_jobs[i].last_committed_lsn);
        for (int j = 0; j < rec->pending_job_rec_cnt; ++j) {
            app_debug(true, 0, "    Job_Rec: %lu, %lu", rec->pending_jobs[i].job_id, rec->pending_job_records[j].job_id);
            if (rec->pending_job_records[j].job_id == rec->pending_jobs[i].job_id) {
                app_debug(true, 0, "        Rec_off: %u", rec->pending_job_records[j].rec_off);
                app_debug(true, 0, "        Rec_len: %u", rec->pending_job_records[j].rec_len);
            }
        }
    }
}

void aura_db_wal_scan(AURA_DBHANDLE _db) {
    AURA_DB *db;
    struct aura_db_wal_rec_hdr wal_hdr;
    struct aura_db_rec_hdr rec_hdr;
    off_t offset;
    ssize_t res;

    db = (AURA_DB *)_db;
    offset = sizeof(struct aura_db_wal_hdr);

    app_debug(true, 0, "wal DB file size: %u", db->db_file_hdr.file_size);
    while (true) {
        app_debug(true, 0, "wal DB read offset: %u", offset);
        res = pread(db->wal_fd, &wal_hdr, sizeof(wal_hdr), offset);
        if (res == 0)
            break;
        res = pread(db->wal_fd, &rec_hdr, sizeof(rec_hdr), offset + sizeof(wal_hdr));

        a_db_dump_wal_header(&wal_hdr);
        a_db_dump_rec_header(&rec_hdr);
        offset += wal_hdr.rec_len;
    }
}

void aura_db_scan(AURA_DBHANDLE _db) {
    AURA_DB *db;
    struct aura_db_rec_hdr rec_hdr;
    off_t offset;
    ssize_t res;

    db = (AURA_DB *)_db;
    offset = db->db_file_hdr.record_off;

    app_debug(true, 0, "DB file size: %u", db->db_file_hdr.file_size);
    while (offset < db->db_file_hdr.file_size) {
        app_debug(true, 0, "DB read offset: %u", offset);
        res = pread(db->db_fd, &rec_hdr, sizeof(rec_hdr), offset);

        a_db_dump_rec_header(&rec_hdr);
        offset += rec_hdr.rec_len.aligned_len;
    }
}
