#include "db/db.h"
#include "file_lib.h"
#include "hash_lib.h"
#include "time_lib.h"
#include "utils_lib.h"

#include <errno.h>
#include <fcntl.h> /* open & db_open flags */
#include <stdarg.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/uio.h> /* struct iovec */
#include <unistd.h>

struct aura_db_hdr {
    u_int32_t magic;
    u_int16_t version;
    u_int16_t flags;
    u_int64_t created_ts;
    u_int64_t last_compact_ts;
    u_int32_t hash_algo;
    off_t bucket_off;
    u_int32_t bucket_cnt;
    off_t record_off;
    u_int64_t file_size;
};

#define A_DB_MAGIC 0x5D5D5D5D
#define A_DB_REC_MAGIC 0xED5EC001
#define A_DB_WAL_MAGIC 0xED3A1001
#define A_BUCKET_TAB_OFFSET sizeof(struct aura_db_hdr)
#define A_DB_BUF_SIZE 4096
#define A_DB_VERSION 0x10000U

/* Dump database header */
void aura_db_dump_db_header(struct aura_db_hdr *hdr);

/**
 * @todo: can I mmap the entire db file?
 * Point to it from DB_HANDLE perhaps!
 */

/*
 * Library's private representation of the database.
 */
typedef struct {
    int db_fd;                            /* fd for db file */
    int wal_fd;                           /* fd for WAL file */
    char *name;                           /* database file name */
    struct aura_db_hdr db_hdr;            /* database header */
    struct aura_db_bucket_entry *buckets; /* hash buckets */
    u_int32_t cnt_delok;                  /* delete OK */
    u_int32_t cnt_delerr;                 /* delete error */
    u_int32_t cnt_fetchok;                /* fetch OK */
    u_int32_t cnt_fetcherr;               /* fetch error */
    u_int32_t cnt_nextrec;                /* nextrec */
    u_int32_t cnt_stor1;                  /* store: DB_INSERT, no empty, appended */
    u_int32_t cnt_stor2;                  /* store: DB_INSERT, found empty, reused */
    u_int32_t cnt_stor3;                  /* store: DB_REPLACE, diff len, appended */
    u_int32_t cnt_stor4;                  /* store: DB_REPLACE, same len, overwrote */
    u_int32_t cnt_storerr;                /* store error */
} AURA_DB;

typedef enum {
    A_WAL_PUT = 1,
    A_WAL_DEL = 2
} aura_db_wal_ops;

/*
 * Internal functions.
 */
static AURA_DB *a_db_alloc(int);
static void a_db_free(AURA_DB *);
static off_t a_db_wal_commit(int wal_fd, uint16_t namespace, uint16_t schema_id,
                             int wal_op, struct aura_iovec *key, struct aura_iovec *data,
                             struct aura_db_rec_len *rec_len);
static int a_db_wal_replay(AURA_DB *);

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

    db = calloc(1, sizeof(AURA_DB));
    if (!db)
        sys_exit(true, errno, "a_db_alloc: DB error");
    /* init db file descriptor */
    db->db_fd = -1;

    /* Null terminated string */
    db->name = malloc(namelen + 1);
    if (!db->name)
        sys_exit(true, errno, "a_db_alloc: name error");

    return db;
}

/* Save db meta data */
static inline ssize_t a_db_write_db_meta(AURA_DB *db) {
    struct iovec iov[2];

    iov[0].iov_base = &db->db_hdr;
    iov[0].iov_len = sizeof(struct aura_db_hdr);
    iov[1].iov_base = db->buckets;
    iov[1].iov_len = db->db_hdr.bucket_cnt * sizeof(struct aura_db_bucket_entry);

    return writev(db->db_fd, iov, 2);
}

/* Read db meta data */
static inline ssize_t a_db_read_db_meta(AURA_DB *db) {
    struct iovec iov[2];

    iov[0].iov_base = &db->db_hdr;
    iov[0].iov_len = sizeof(struct aura_db_hdr);
    iov[1].iov_base = db->buckets;
    iov[1].iov_len = A_DB_BUCKET_CNT * sizeof(struct aura_db_bucket_entry);

    return readv(db->db_fd, iov, 2);
}

/*
 * Open or create a database.  Same arguments as open(2).
 */
AURA_DBHANDLE aura_db_open(const char *db_pathname, int oflag, ...) {
    AURA_DB *db;
    int db_namelen, mode;
    size_t i, bucket_arr_size;
    ssize_t res;
    struct stat statbuf;

    /* Allocate a DB structure, and the buffers it needs. */
    db_namelen = strlen(db_pathname);
    db = a_db_alloc(db_namelen);
    if (!db)
        sys_exit(true, errno, "db_open error");

    bucket_arr_size = sizeof(struct aura_db_bucket_entry) * A_DB_BUCKET_CNT;
    db->buckets = malloc(bucket_arr_size);
    if (!db->buckets)
        sys_exit(true, errno, "db_open: db->buckets error");
    memset(db->buckets, 0, bucket_arr_size);

    strcpy(db->name, db_pathname);

    if (oflag & O_CREAT) {
        va_list ap;

        va_start(ap, oflag);
        mode = va_arg(ap, int);
        va_end(ap);

        /* Open index file and data file. */
        db->db_fd = open(db->name, oflag, mode);

        if (db->db_fd < 0) {
            if (errno != EEXIST)
                goto exception;

            if (errno == EEXIST) {
                /* Open normally */
                oflag &= ~(O_CREAT | O_TRUNC | O_EXCL);
                db->db_fd = open(db->name, oflag);
            }
        }
    } else {
        db->db_fd = open(db->name, oflag);
    }

    if (db->db_fd < 0)
        goto exception;

    if ((oflag & (O_CREAT | O_TRUNC)) == (O_CREAT | O_TRUNC)) {
        /*
         * If the database was created, we have to initialize
         * it.  Write lock the entire file so that we can stat
         * it, check its size, and initialize it, atomically.
         */
        if (a_writew_lock(db->db_fd, 0, SEEK_SET, 0) < 0)
            sys_exit(true, errno, "db_open: writew_lock error");

        if (fstat(db->db_fd, &statbuf) < 0)
            sys_exit(true, errno, "db_open: fstat error");

        i = sizeof(struct aura_db_hdr);
        if (statbuf.st_size == 0) {
            /* Build db, initialize db header */
            db->db_hdr.magic = A_DB_MAGIC;
            db->db_hdr.version = (uint16_t)0x10000; /* 1.0.0 */
            db->db_hdr.hash_algo = A_FNV1A_HASH_ALGO;
            db->db_hdr.created_ts = aura_now_ms();
            db->db_hdr.flags = 0;
            db->db_hdr.last_compact_ts = 0;
            db->db_hdr.bucket_cnt = A_DB_BUCKET_CNT;
            db->db_hdr.bucket_off = A_BUCKET_TAB_OFFSET;
            db->db_hdr.record_off = A_BUCKET_TAB_OFFSET + (A_DB_BUCKET_CNT * sizeof(void *));
            db->db_hdr.file_size = sizeof(struct aura_db_hdr) + bucket_arr_size;

            res = a_db_write_db_meta(db);
            if (res < 0)
                sys_exit(true, errno, "db_open: db file init write error");
        }
        if (a_unlock(db->db_fd, 0, SEEK_SET, 0) < 0)
            sys_exit(true, errno, "db_open: un_lock error");
    } else {
        /* read db hdr and buckets into their buffers */
        res = lseek(db->db_fd, 0, SEEK_SET);
        if (res < 0)
            goto exception;

        if (a_readw_lock(db->db_fd, 0, SEEK_SET, 0) < 0)
            sys_exit(true, errno, "db_open: a_readw_lock error");

        res = a_db_read_db_meta(db);
        if (res < 0)
            goto exception;

        if (a_unlock(db->db_fd, 0, SEEK_SET, 0) < 0)
            sys_exit(true, errno, "db_open: un_lock error");
    }

    a_db_rewind(db->db_fd);
    return db;
exception:
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
    if (db->name != NULL)
        free(db->name);
    free(db);
}

/*
 * Relinquish access to the database.
 */
void aura_db_close(AURA_DBHANDLE h) {
    a_db_free((AURA_DB *)h); /* closes fds, free buffers & struct */
}

/* Write header back to db */
static ssize_t a_db_write_bucket_array(AURA_DB *db) {
    ssize_t res;

    res = lseek(db->db_fd, 0, SEEK_SET);
    if (res < 0)
        return -1;

    if (a_writew_lock(db->db_fd, 0, SEEK_SET, 0) < 0)
        sys_exit(true, errno, "a_db_write_bucket_array: a_writew_lock error");

    res = a_db_write_db_meta(db);

    if (a_unlock(db->db_fd, 0, SEEK_SET, 0) < 0)
        sys_exit(true, errno, "a_db_write_bucket_array: a_unlock error");

    return res;
}

static inline int a_db_append_record(int fd, struct aura_db_rec_hdr *hdr, const void *key, const void *data,
                                     struct aura_db_rec_len *rec_len, off_t start_offset) {
    struct iovec iov[3];
    off_t offset;
    ssize_t written;
    static const uint64_t db_zero = 0;

    iov[0].iov_base = hdr;
    iov[0].iov_len = sizeof(*hdr);
    iov[1].iov_base = (void *)key;
    iov[1].iov_len = hdr->key_len;
    iov[2].iov_base = (void *)data;
    iov[2].iov_len = hdr->data_len;

    if (a_writew_lock(fd, 0, SEEK_SET, 0) < 0)
        sys_exit(true, errno, "a_db_append_record: a_writew_lock error");

    /* Append the record */
    if (start_offset == 0) {
        offset = lseek(fd, 0, SEEK_END);
    } else {
        offset = lseek(fd, start_offset, SEEK_SET);
    }
    if (offset < 0)
        return -1;

    written = writev(fd, iov, 3);
    if (written != rec_len->raw_len)
        return -1;

    /* Add padding */
    if (rec_len->aligned_len > rec_len->raw_len) {
        written = write(fd, &db_zero, rec_len->aligned_len - rec_len->raw_len);
        if (written != (rec_len->aligned_len - rec_len->raw_len)) {
            /* Nothing fatal here! We can proceed I think*/
        }
    }

    if (a_unlock(fd, 0, SEEK_SET, 0) < 0)
        sys_exit(true, errno, "a_db_append_record: a_unlock error");

    return offset;
}

int aura_db_put_record(AURA_DBHANDLE _db, uint16_t namespace, uint16_t schema_id, struct aura_iovec *key, struct aura_iovec *data) {
    struct aura_db_rec_hdr *rec_hdr;
    uint32_t hash, old_head;
    off_t offset;
    char *rec_hdr_buf[sizeof(*rec_hdr)];
    struct aura_iovec data_checksum;
    ssize_t res;
    AURA_DB *db;
    size_t db_file_size;

    db = (AURA_DB *)_db;
    hash = a_fnv1a_hash(db->db_hdr.bucket_cnt, namespace, key);
    old_head = db->buckets[hash].head_off;

    data_checksum = aura_calculate_digest(data);
    if (data_checksum.base == NULL && data->base != NULL) {
        app_debug(true, 0, "aura_db_put_record: aura_calculate_digest error");
        return -1;
    }

    rec_hdr = (struct aura_db_rec_hdr *)rec_hdr_buf;
    rec_hdr->magic = A_DB_REC_MAGIC;
    rec_hdr->version = A_DB_VERSION;
    rec_hdr->ns = namespace;
    rec_hdr->flags = 0;
    rec_hdr->schema_id = schema_id;
    rec_hdr->prev_off = old_head;
    rec_hdr->timestamp = aura_now_ms();
    rec_hdr->rec_len = a_get_db_record_len(key->len, data->len);
    rec_hdr->key_len = key->len;
    rec_hdr->data_len = data->len;
    memcpy(rec_hdr->check_sum, data_checksum.base, DIGEST_LEN);

    offset = a_db_append_record(
      db->db_fd, rec_hdr,
      (const void *)key->base,
      (const void *)data->base,
      &rec_hdr->rec_len,
      old_head < db->db_hdr.record_off ? db->db_hdr.record_off : 0);

    if (offset == -1)
        return -1;

    /* @todo: WAL commit */

    /* store new bucket entry head */
    db_file_size = __atomic_load_n(&db->db_hdr.file_size, __ATOMIC_ACQUIRE);
    __atomic_store_n(&db->buckets[hash].head_off, offset, __ATOMIC_RELEASE);
    __atomic_store_n(&db->db_hdr.file_size, db_file_size + rec_hdr->rec_len.aligned_len, __ATOMIC_RELEASE);
    res = a_db_write_bucket_array(db);
    if (res < 0)
        return -1;

    return 0;
}

void aura_db_record_free(void *record) {
    if (!record)
        return;

    free(record);
}

bool aura_db_record_exists(AURA_DBHANDLE _db, uint16_t namespace, uint16_t scheme_id, struct aura_iovec *key) {
    struct aura_db_rec_hdr rec_hdr;
    uint32_t hash;
    AURA_DB *db;
    off_t offset;
    ssize_t res;
    char key_buf[4096];

    db = (AURA_DB *)_db;
    hash = a_fnv1a_hash(db->db_hdr.bucket_cnt, namespace, key);
    offset = db->buckets[hash].head_off;

    while (offset != 0) {
        res = pread(db->db_fd, &rec_hdr, sizeof(rec_hdr), offset);
        if (res < 0)
            goto exception;

        aura_db_dump_rec_header(&rec_hdr);
        if (rec_hdr.magic != A_DB_REC_MAGIC)
            break;

        memset(key_buf, 0, sizeof(key_buf));
        if (rec_hdr.ns == namespace && rec_hdr.key_len == key->len) {
            res = pread(db->db_fd, key_buf, key->len, offset + sizeof(rec_hdr));
            if (res < 0)
                goto exception;

            if (aura_mem_is_eq(key_buf, strlen(key_buf), key->base, key->len)) {
                if (rec_hdr.flags & A_DB_REC_TOMBSTONE)
                    return false;
                return true;
            }
        }

        offset = rec_hdr.prev_off;
    }

    return false;
exception:
    sys_exit(true, errno, "aura_db_record_exists error");
}

int aura_db_fetch_record(AURA_DBHANDLE _db, uint16_t namespace, struct aura_iovec *key, struct aura_iovec *data_out) {
    struct aura_db_rec_hdr rec_hdr;
    uint32_t hash;
    off_t offset;
    ssize_t res;
    char *record;
    char key_buf[4096];
    AURA_DB *db;

    db = (AURA_DB *)_db;
    hash = a_fnv1a_hash(db->db_hdr.bucket_cnt, namespace, key);
    offset = db->buckets[hash].head_off;

    record = NULL;
    while (offset != 0) {
        res = pread(db->db_fd, &rec_hdr, sizeof(rec_hdr), offset);
        if (res < 0)
            goto exception;

        if (rec_hdr.magic != A_DB_REC_MAGIC)
            break;

        memset(key_buf, 0, sizeof(key_buf));
        if (rec_hdr.ns == namespace && rec_hdr.key_len == key->len) {
            res = pread(db->db_fd, key_buf, key->len, offset + sizeof(rec_hdr));
            if (res < 0)
                goto exception;

            if (aura_mem_is_eq(key_buf, strlen(key_buf), key->base, key->len)) {
                if (rec_hdr.flags & A_DB_REC_TOMBSTONE)
                    return A_DB_REC_NOT_FOUND;

                record = malloc(rec_hdr.data_len);
                if (!record)
                    goto exception;

                res = pread(db->db_fd, record, rec_hdr.data_len, offset + sizeof(rec_hdr) + rec_hdr.key_len);
                if (res < 0) {
                    free(record); /* probably no need to free record, since I am exiting for now */
                    goto exception;
                }
                data_out->base = record;
                data_out->len = rec_hdr.data_len;
                return 0;
            }
        }

        offset = rec_hdr.prev_off;
    }

    if (record)
        aura_db_record_free(record);
    return A_DB_REC_NOT_FOUND;

exception:
    sys_exit(true, errno, "aura_db_put_record error");
}

int aura_db_delete_record(AURA_DBHANDLE _db, uint16_t namespace, uint16_t schema_id, struct aura_iovec *key) {
    struct aura_db_rec_hdr rec_hdr;
    uint32_t hash;
    AURA_DB *db;
    off_t old_head, offset;
    struct aura_db_rec_len rec_len;

    db = (AURA_DB *)_db;
    rec_len = a_get_db_record_len(key->len, 0);
    offset = a_db_wal_commit(db->wal_fd, namespace, schema_id, A_WAL_DEL, key, NULL, &rec_len);
    if (offset < 0)
        return -1;

    hash = a_fnv1a_hash(db->db_hdr.bucket_cnt, namespace, key);
    old_head = db->buckets[hash].head_off;

    rec_hdr.magic = A_DB_REC_MAGIC;
    rec_hdr.ns = namespace;
    rec_hdr.schema_id = schema_id;
    rec_hdr.version = A_DB_VERSION;
    rec_hdr.flags &= A_DB_REC_TOMBSTONE;
    rec_hdr.timestamp = aura_now_ms();
    rec_hdr.key_len = key->len;
    rec_hdr.data_len = 0;
    rec_hdr.rec_len = rec_len;
    rec_hdr.prev_off = old_head;

    offset = a_db_append_record(
      db->db_fd,
      &rec_hdr,
      (const void *)key->base,
      NULL,
      &rec_hdr.rec_len,
      old_head < db->db_hdr.record_off ? db->db_hdr.record_off : 0);

    if (offset == -1)
        return -1;

    __atomic_store_n(&db->buckets[hash].head_off, offset, __ATOMIC_RELEASE);
    return 0;
}

/**
 * Construct buckets array from records.
 * This is done after compacting the database
 * inorder to restore correct database metadata
 */
static void a_db_buckets_rebuild(AURA_DB *db) {
    off_t offset;
    uint32_t hash;
    struct aura_db_rec_hdr rec_hdr;
    ssize_t res;
    char key_buf[4096];
    struct aura_iovec key;

    memset(db->buckets, 0, db->db_hdr.bucket_cnt * sizeof(struct aura_db_bucket_entry));
    offset = db->db_hdr.record_off;

    while (offset < db->db_hdr.file_size) {
        res = pread(db->db_fd, &rec_hdr, sizeof(rec_hdr), offset);
        if (res < 0)
            sys_exit(true, errno, "aura_db_bucket_rebuild: pread error");

        if (rec_hdr.magic != A_DB_REC_MAGIC)
            break;

        res = pread(db->db_fd, key_buf, rec_hdr.key_len, offset + sizeof(rec_hdr));
        if (res < 0)
            sys_exit(true, errno, "aura_db_bucket_rebuild: pread error");

        key.base = key_buf;
        key.len = rec_hdr.key_len;
        hash = a_fnv1a_hash(db->db_hdr.bucket_cnt, rec_hdr.ns, &key);

        __atomic_store_n(&rec_hdr.prev_off, db->buckets[hash].head_off, __ATOMIC_RELEASE);
        __atomic_store_n(&db->buckets[hash].head_off, offset, __ATOMIC_RELEASE);
        offset += rec_hdr.rec_len.aligned_len;
    }
}

static inline off_t a_db_wal_append(int wal_fd, struct aura_db_wal_rec_hdr *wal_hdr, const void *key, const void *data) {
    off_t offset;
    struct iovec iov[3];
    ssize_t res;

    if (a_writew_lock(wal_fd, 0, SEEK_SET, 0) < 0)
        sys_exit(true, errno, "a_db_wal_append: a_writew_lock error:");

    if (lseek(wal_fd, 0, SEEK_END) < 0)
        sys_exit(true, errno, "a_db_wal_append: lseek error:");

    iov[0].iov_base = wal_hdr;
    iov[0].iov_len = sizeof(*wal_hdr);
    iov[1].iov_base = (void *)key;
    iov[1].iov_len = wal_hdr->key_len;
    iov[2].iov_base = NULL;
    iov[2].iov_len = 0;
    if (wal_hdr->op == A_WAL_PUT) {
        iov[2].iov_base = (void *)data;
        iov[2].iov_len = wal_hdr->data_len;
    }

    res = writev(wal_fd, iov, 3);
    if (res < 0)
        sys_exit(true, errno, "a_db_wal_append: writev error:");

    if (a_unlock(wal_fd, 0, SEEK_SET, 0) < 0)
        sys_exit(true, errno, "a_db_wal_append: a_writew_lock error:");

    fdatasync(wal_fd);
    return offset;
}

/**
 * Write operation to WAL file
 */
static off_t a_db_wal_commit(int wal_fd, uint16_t namespace, uint16_t schema_id,
                             int wal_op, struct aura_iovec *key, struct aura_iovec *data,
                             struct aura_db_rec_len *rec_len) {
    struct aura_db_wal_rec_hdr wal_hdr;
    off_t offset;

    wal_hdr.magic = A_DB_WAL_MAGIC;
    wal_hdr.op = wal_op;
    wal_hdr.ns = namespace;
    wal_hdr.schema_id = schema_id;
    wal_hdr.key_len = key->len;
    wal_hdr.data_len = data->len;
    wal_hdr.timestamp = aura_now_ms();
    wal_hdr.rec_len = *rec_len;

    offset = a_db_wal_append(wal_fd, &wal_hdr, (const void *)key->base, (const void *)data->base);
    return offset;
}

/**
 * Replay operations from WAL file and restore db to
 * achieve consistent state.
 */
static int a_db_wal_replay(AURA_DB *db) {
    struct aura_db_wal_rec_hdr hdr;
    off_t offset;
    ssize_t res;
    struct aura_iovec key, data;
    char key_buf[4096];
    int ok;
    char *data_buf;

    offset = 0;
    while (true) {
        res = pread(db->wal_fd, &hdr, sizeof(hdr), offset);
        if (res == 0)
            /* EOF */
            return 0;

        if (res != sizeof(hdr))
            break;

        if (hdr.magic != A_DB_WAL_MAGIC)
            break;

        res = pread(db->wal_fd, key_buf, hdr.key_len, offset + sizeof(hdr));
        if (res != hdr.key_len)
            break;

        key.base = key_buf;
        key.len = hdr.key_len;
        if (hdr.op == A_WAL_PUT) {
            data_buf = malloc(hdr.data_len);
            if (!data_buf)
                break;

            res = pread(db->wal_fd, data_buf, hdr.data_len, offset + sizeof(hdr) + hdr.key_len);
            if (res != hdr.data_len) {
                free(data_buf);
                break;
            }

            data.base = data_buf;
            data.len = hdr.data_len;
            ok = aura_db_put_record((AURA_DBHANDLE)db, hdr.ns, hdr.schema_id, &key, &data);
        } else if (hdr.op == A_WAL_DEL) {
            ok = aura_db_delete_record((AURA_DBHANDLE)db, hdr.ns, hdr.schema_id, &key);
        }
        offset += hdr.rec_len.aligned_len;
    }

    return 1;
}

struct aura_db_compact_table {
    char *key_buf;
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
    snprintf(comp_tab->key_buf + comp_tab->key_off, comp_tab_entry_len, "%u%s", hdr->key_len, key);
    comp_tab->key_off += comp_tab_entry_len;
    comp_tab->cnt++;
}

/**
 * Compact database and prune deleted records
 * @todo: improve!!
 */
static int a_db_compact(AURA_DB *db) {
    struct aura_db_rec_hdr rec_hdr;
    off_t read_off, write_off;
    struct aura_db_compact_table comp_tab;
    ssize_t res;
    size_t comp_tab_entry_len, key_len, new_file_size, bucket_arr_size;
    char buf[4096], *data_buf;
    bool record_deleted;
    off_t offset;
    char compact_file_path[256], *ptr;
    int new_fd;

    comp_tab.key_buf = malloc(65536); /* 64KB */
    comp_tab.cnt = comp_tab.key_off = 0;
    comp_tab.cap = 65536;
    read_off = db->db_hdr.record_off;
    write_off = 0;
    bucket_arr_size = sizeof(struct aura_db_bucket_entry) * A_DB_BUCKET_CNT;
    new_file_size = sizeof(struct aura_db_hdr) + bucket_arr_size;

    /* Construct compact_file_path */
    size_t len;
    ptr = strrchr(db->name, '/');
    len = ptr - db->name + 2;
    snprintf(compact_file_path, len, "%s", db->name);
    strcat(compact_file_path, AURA_DB_COMPACT_FILE);
    new_fd = open(compact_file_path, O_RDWR | O_CREAT | O_TRUNC, S_IRWXU);
    if (new_fd < 0)
        return -1;

    if (a_writew_lock(db->db_fd, 0, SEEK_SET, 0) < 0)
        sys_exit(true, errno, "a_db_compact: a_writew_lock:");

    while (read_off < db->db_hdr.file_size) {
        res = pread(db->db_fd, &rec_hdr, sizeof(rec_hdr), read_off);
        if (res != sizeof(rec_hdr))
            goto err_out_fd;

        res = pread(db->db_fd, buf, rec_hdr.key_len, read_off + sizeof(rec_hdr));
        if (res != rec_hdr.key_len)
            goto err_out_fd;

        if (rec_hdr.flags & A_DB_REC_TOMBSTONE) {
            /* Record deleted record in compaction table */
            a_db_compact_table_append(&comp_tab, &rec_hdr, buf);
            read_off += rec_hdr.rec_len.aligned_len;
            continue;
        }

        /* Search compaction table if this record was deleted */
        record_deleted = false;
        for (int i = 0, key_off = 0; i < comp_tab.cnt; ++i) {
            aura_scan_str(comp_tab.key_buf + key_off, "%lu", &key_len);
            if (aura_mem_is_eq(buf, rec_hdr.key_len, &comp_tab.key_buf[sizeof(size_t) + key_off], key_len)) {
                record_deleted = true;
                break;
            }
            key_off += sizeof(size_t) + key_len;
        }

        if (record_deleted) {
            /* Skip */
            read_off += rec_hdr.rec_len.aligned_len;
            continue;
        } else {
            /* Append to new db file */
            data_buf = malloc(rec_hdr.data_len);
            if (!data_buf)
                goto err_out_fd;

            res = pread(db->db_fd, data_buf, rec_hdr.data_len, read_off + sizeof(rec_hdr) + rec_hdr.key_len);
            if (res != rec_hdr.data_len) {
                free(data_buf);
                goto err_out_fd;
            }

            write_off = a_db_append_record(
              new_fd, &rec_hdr,
              (const void *)buf,
              (const void *)data_buf,
              &rec_hdr.rec_len,
              0);

            if (offset < 0) {
                free(data_buf);
                goto err_out_fd;
            }

            read_off += rec_hdr.rec_len.aligned_len;
            new_file_size += rec_hdr.rec_len.aligned_len;
        }
    }

    /* Copy updated records back to original file */
    a_db_rewind(new_fd);
    if (lseek(db->db_fd, db->db_hdr.record_off, SEEK_SET) < 0)
        sys_exit(true, errno, "a_db_compact: a_writew_lock:");

    ssize_t bytes_read, bytes_written;
    do {
        bytes_read = aura_read_n(new_fd, buf, sizeof(buf));
        bytes_written = aura_write_n(db->db_fd, buf, bytes_read);
    } while (bytes_read > 0 && bytes_written > 0);

    /* Rebuild bucket array */
    __atomic_store_n(&db->db_hdr.file_size, new_file_size, __ATOMIC_RELEASE);
    a_db_buckets_rebuild(db);
    res = a_db_write_db_meta(db);
    if (res < 0) {
        free(data_buf);
        goto err_out_fd;
    }

    if (a_writew_lock(db->db_fd, 0, SEEK_SET, 0) < 0)
        sys_exit(true, errno, "a_db_compact: a_writew_lock:");

    close(new_fd);
    return 0;

err_out_fd:
    if (a_writew_lock(db->db_fd, 0, SEEK_SET, 0) < 0)
        sys_exit(true, errno, "a_db_compact: a_writew_lock:");

    close(new_fd);
    return -1;
}

void aura_db_dump_db_header(struct aura_db_hdr *hdr) {
    app_debug(true, 0, "AURA DB HEADER");
    app_debug(true, 0, "    Magic: %zu", hdr->magic);
    app_debug(true, 0, "    Version: %zu", hdr->version);
    app_debug(true, 0, "    Flags: %zu", hdr->flags);
    app_debug(true, 0, "    Created at: %zu", hdr->created_ts);
    app_debug(true, 0, "    Hash algorithm: %zu", hdr->hash_algo);
    app_debug(true, 0, "    Bucket off: %zu", hdr->bucket_off);
    app_debug(true, 0, "    Bucket count: %zu", hdr->bucket_cnt);
    app_debug(true, 0, "    File size: %zu", hdr->file_size);
    app_debug(true, 0, "    Last compaction at: %zu", hdr->last_compact_ts);
}

void aura_db_dump_rec_header(struct aura_db_rec_hdr *hdr) {
    app_debug(true, 0, "AURA DB RECORD HEADER");
    app_debug(true, 0, "    Magic: %zu", hdr->magic);
    app_debug(true, 0, "    Version: %zu", hdr->version);
    app_debug(true, 0, "    Namespace: %zu", hdr->ns);
    app_debug(true, 0, "    Schema Id: %zu", hdr->schema_id);
    app_debug(true, 0, "    Flags: %zu", hdr->flags);
    app_debug(true, 0, "    Key len: %zu", hdr->key_len);
    app_debug(true, 0, "    Data len: %zu", hdr->data_len);
    app_debug(true, 0, "    Record len: %zu", hdr->rec_len);
    app_debug(true, 0, "    Previous offset: %zu", hdr->prev_off);
    app_debug(true, 0, "    Timestamp: %zu", hdr->timestamp);
}
