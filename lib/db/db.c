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
#define A_BUCKET_TAB_OFFSET sizeof(struct aura_db_hdr)
#define A_DB_BUF_SIZE 4096

/**
 * @todo: can I mmap the entire db file?
 * Point to it from DB_HANDLE perhaps!
 */

/*
 * Library's private representation of the database.
 */
typedef struct {
    int db_fd;                            /* fd for db file */
    char *db_buf;                         /* malloc'ed buffer for db records */
    char *name;                           /* name db was opened under */
    struct aura_db_bucket_entry *buckets; /* hash buckets */
    u_int64_t bucket_off;                 /* offset for bucket array */
    u_int64_t bucket_cnt;                 /* length of bucket array */
    u_int64_t record_off;                 /* offset for record */
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

/*
 * Internal functions.
 */
static AURA_DB *a_db_alloc(int);
static void a_db_free(AURA_DB *);

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
        sys_exit(true, errno, "a_db_alloc: calloc error for DB");
    /* init db file descriptor */
    db->db_fd = -1;

    /* Null terminated string */
    db->name = malloc(namelen + 1);
    if (!db->name)
        sys_exit(true, errno, "a_db_alloc: malloc error for name");

    db->db_buf = malloc(4096);
    if (!db->db_buf)
        sys_exit(true, errno, "a_db_alloc: malloc error for index buffer");
    return db;
}

/*
 * Open or create a database.  Same arguments as open(2).
 */
AURA_DBHANDLE aura_db_open(const char *pathname, int oflag, ...) {
    AURA_DB *db;
    struct aura_db_hdr *db_hdr;
    int len, mode;
    size_t i, bucket_arr_size;
    ssize_t res;
    struct stat statbuf;
    char *db_hdr_buf[sizeof(*db_hdr)];

    /* Allocate a DB structure, and the buffers it needs. */
    len = strlen(pathname);
    db = a_db_alloc(len);
    if (!db)
        sys_exit(true, errno, "db_open error");

    bucket_arr_size = sizeof(struct aura_db_bucket_entry) * A_DB_BUCKET_CNT;
    db->bucket_cnt = A_DB_BUCKET_CNT;
    db->bucket_off = A_BUCKET_TAB_OFFSET;
    db->record_off = A_BUCKET_TAB_OFFSET + (A_DB_BUCKET_CNT * sizeof(void *));
    db->buckets = malloc(bucket_arr_size);
    if (!db->buckets)
        sys_exit(true, errno, "db_open: db->buckets error");
    memset(db->buckets, 0, bucket_arr_size);

    strcpy(db->name, pathname);

    if (oflag & O_CREAT) {
        va_list ap;

        va_start(ap, oflag);
        mode = va_arg(ap, int);
        va_end(ap);

        /* Open index file and data file. */
        db->db_fd = open(db->name, oflag, mode);
    }

    if (db->db_fd < 0 && errno != EEXIST)
        goto exception;

    if (errno == EEXIST) {
        oflag &= ~(O_CREAT | O_TRUNC | O_EXCL);
        db->db_fd = open(db->name, oflag);
    }

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

        i = sizeof(*db_hdr);
        if (statbuf.st_size == 0) {
            /* Build db, initialize header */
            db_hdr = (struct aura_db_hdr *)(db_hdr_buf);
            db_hdr->magic = A_DB_MAGIC;
            db_hdr->bucket_cnt = db->bucket_cnt;
            db_hdr->bucket_off = db->bucket_off;
            db_hdr->record_off = db->record_off;
            db_hdr->version = (uint16_t)0x10000; /* 1.0.0 */
            db_hdr->created_ts = aura_now_ms();
            db_hdr->file_size = 0;
            db_hdr->flags = 0;
            db_hdr->hash_algo = 0;
            db_hdr->last_compact_ts = 0;

            res = write(db->db_fd, db_hdr_buf, i);
            if (res != i)
                sys_exit(true, errno, "db_open: db file init write error");
        }
        if (a_unlock(db->db_fd, 0, SEEK_SET, 0) < 0)
            sys_exit(true, errno, "db_open: un_lock error");
    } else {
        /* read bucket into buffer */
        res = lseek(db->db_fd, db->bucket_off, SEEK_SET);
        if (res < 0)
            goto exception;

        if (a_readw_lock(db->db_fd, db->bucket_off, SEEK_SET, 0) < 0)
            sys_exit(true, errno, "db_open: a_readw_lock error");

        res = read(db->db_fd, db->buckets, bucket_arr_size);
        if (res < 0)
            goto exception;

        if (a_unlock(db->db_fd, db->bucket_off, SEEK_SET, 0) < 0)
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
    if (db->db_buf != NULL)
        free(db->db_buf);
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
static int a_db_write_bucket_array(AURA_DB *db) {
    ssize_t res;

    res = lseek(db->db_fd, db->bucket_off, SEEK_SET);
    if (res < 0)
        return -1;

    if (a_writew_lock(db->db_fd, db->bucket_off, SEEK_SET, 0) < 0)
        sys_exit(true, errno, "a_db_write_bucket_array: a_writew_lock error");

    res = write(db->db_fd, db->buckets, db->bucket_cnt * sizeof(struct aura_db_bucket_entry));

    if (a_unlock(db->db_fd, db->bucket_off, SEEK_SET, 0) < 0)
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
    if (offset == 0) {
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

    db = (AURA_DB *)_db;
    hash = a_fnv1a_hash(db->bucket_cnt, namespace, key);
    old_head = db->buckets[hash].head_off;

    data_checksum = aura_calculate_digest(data);
    if (data_checksum.base == NULL) {
        app_debug(true, 0, "aura_db_put_record: aura_calculate_digest");
        return -1;
    }

    rec_hdr = (struct aura_db_rec_hdr *)rec_hdr_buf;
    rec_hdr->magic = A_DB_REC_MAGIC;
    rec_hdr->version = 0x10000;
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
      old_head < db->record_off ? db->record_off : 0);

    if (offset == -1)
        return -1;

    /* @todo: WAL commit */

    /* store new bucket entry head */
    __atomic_store_n(&db->buckets[hash].head_off, offset, __ATOMIC_RELEASE);
    res = a_db_write_bucket_array(db);
    if (res < 0)
        return -1;

    return 0;

exception:
    sys_exit(true, errno, "aura_db_put_record");
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
    hash = a_fnv1a_hash(db->bucket_cnt, namespace, key);
    offset = db->buckets[hash].head_off;

    while (offset != 0) {
        res = pread(db->db_fd, &rec_hdr, sizeof(rec_hdr), offset);
        if (res < 0)
            goto exception;

        aura_db_dump_rec_hdr(&rec_hdr);
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
    hash = a_fnv1a_hash(db->bucket_cnt, namespace, key);
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

void aura_db_dump_rec_hdr(struct aura_db_rec_hdr *hdr) {
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
