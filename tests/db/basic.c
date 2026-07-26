#include "db/db.h"

#include <assert.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

struct aura_mem_ctx mc;
struct _aura_db;

static char test_dir[128] = {0};
static char ctrl_file[256] = {0};
static char data_file[256] = {0};
static char wal_file[256] = {0};

#define A_TEST_NS A_DB_MAX_NAMESPACE
#define A_TEST_SCHEMA_ID A_DB_MAX_NAMESPACE

#define A_DB_TEST_WRITE_CACHE_SZ 4096
#define A_DB_TEST_READ_CACHE_SZ 4096

static void a_setup_temp_db_files(void) {
    int res;

    aura_mem_ctx_init(&mc);
    assert(aura_create_dynamic_slab_alloc_caches(&mc) == 0);

    snprintf(test_dir, sizeof(test_dir), "/tmp/aura_test_db_%u/", getpid());
    assert(mkdir(test_dir, S_IRWXU) == 0);

    memset(ctrl_file, 0, sizeof(ctrl_file));
    memset(data_file, 0, sizeof(data_file));
    memset(wal_file, 0, sizeof(wal_file));

    snprintf(ctrl_file, sizeof(ctrl_file), "%s/aura.ctrl", test_dir);
    snprintf(data_file, sizeof(data_file), "%s/aura.db", test_dir);
    snprintf(wal_file, sizeof(wal_file), "%s/aura_wal.db", test_dir);
}

static void a_cleanup_temp_db_files(void) {
    int res;
    char cmd[512];

    snprintf(cmd, sizeof(cmd), "rm -rf %s", test_dir);
    system(cmd);
    aura_mem_ctx_destroy(&mc);
}

/**
 * Test synchronous insert fetch delete
 * Records makes it to log before user ack
 */
static void a_test_sync_insert_fetch_delete(void) {
    AURA_DBHANDLE db;
    struct aura_iovec key, key1, data, data1;
    struct aura_db_rec rec, rec1;

    db = aura_db_test_open_with_log_writer(
      &mc,
      test_dir,
      O_RDWR,
      A_DB_TEST_WRITE_CACHE_SZ,
      A_DB_TEST_READ_CACHE_SZ,
      A_DB_FILE_MODE);
    assert(db != NULL);
    aura_db_test_fields_with_bg_writer(db);

    /* PUT */
    key.base = "fn:hello_1";
    key.len = strlen(key.base);
    data.base = "World";
    data.len = strlen(data.base);
    assert(aura_db_insert(db, A_TEST_NS, A_TEST_SCHEMA_ID, A_DB_FLAG_NONE, A_DB_INSERT_OP, &key, &data) == 0);

    key1.base = "fn:hello_2";
    key1.len = strlen(key1.base);
    data1.base = "World_2";
    data1.len = strlen(data1.base);
    assert(aura_db_insert(db, A_TEST_NS, A_TEST_SCHEMA_ID, A_DB_FLAG_NONE, A_DB_INSERT_OP, &key1, &data1) == 0);

    /* FETCH */
    /* Write cache must be able to satisfy this */
    assert(aura_db_test_fetch_from_write_cache(db, A_TEST_NS, A_TEST_SCHEMA_ID, &key, &rec) == 0);
    assert(rec.data.len == sizeof("World") - 1);
    assert(strncmp(rec.data.base, "World", data.len) == 0);

    assert(aura_db_test_fetch_from_write_cache(db, A_TEST_NS, A_TEST_SCHEMA_ID, &key1, &rec1) == 0);
    assert(rec1.data.len == sizeof("World_2") - 1);
    assert(strncmp(rec1.data.base, "World_2", data1.len) == 0);

    /* DELETE */
    assert(aura_db_delete(db, A_TEST_NS, A_TEST_SCHEMA_ID, &key) == 0);
    assert(aura_db_delete(db, A_TEST_NS, A_TEST_SCHEMA_ID, &key1) == 0);

    /* FETCH */
    assert(aura_db_test_fetch_from_write_cache(db, A_TEST_NS, A_TEST_SCHEMA_ID, &key, &rec) == A_DB_REC_NOT_FOUND);
    assert(rec.data.base == NULL);
    assert(rec.data.len == 0);

    assert(aura_db_test_fetch_from_write_cache(db, A_TEST_NS, A_TEST_SCHEMA_ID, &key1, &rec1) == A_DB_REC_NOT_FOUND);
    assert(rec1.data.base == NULL);
    assert(rec1.data.len == 0);

    aura_db_test_close_with_bg_writer(db);
}

static void a_test_db_flush_fetch(void) {
    AURA_DBHANDLE db;
    struct aura_iovec key, key1, data, data1;
    struct aura_db_rec rec, rec1;

    db = aura_db_test_open_with_log_writer(
      &mc,
      test_dir,
      O_RDWR,
      A_DB_TEST_WRITE_CACHE_SZ,
      A_DB_TEST_READ_CACHE_SZ,
      A_DB_FILE_MODE);
    assert(db != NULL);
    aura_db_test_fields_with_bg_writer(db);

    /* PUT */
    key.base = "fn:t2_hello_1";
    key.len = strlen(key.base);
    data.base = "t2_World";
    data.len = strlen(data.base);
    assert(aura_db_insert(db, A_TEST_NS, A_TEST_SCHEMA_ID, A_DB_FLAG_NONE, A_DB_INSERT_OP, &key, &data) == 0);

    key1.base = "fn:t2_hello_2";
    key1.len = strlen(key1.base);
    data1.base = "t2_World_2";
    data1.len = strlen(data1.base);
    assert(aura_db_insert(db, A_TEST_NS, A_TEST_SCHEMA_ID, A_DB_FLAG_NONE, A_DB_INSERT_OP, &key1, &data1) == 0);

    assert(aura_db_test_fetch_from_write_cache(db, A_TEST_NS, A_TEST_SCHEMA_ID, &key, &rec) == 0);
    assert(rec.data.len == sizeof("t2_World") - 1);
    assert(strncmp(rec.data.base, "t2_World", data.len) == 0);

    assert(aura_db_test_fetch_from_write_cache(db, A_TEST_NS, A_TEST_SCHEMA_ID, &key1, &rec1) == 0);
    assert(rec1.data.len == sizeof("t2_World_2") - 1);
    assert(strncmp(rec1.data.base, "t2_World_2", data1.len) == 0);

    /* Force write cache flush */
    assert(aura_db_test_force_write_cache_flush(db) == 0);
    aura_db_test_write_cache_reset(db);

    assert(aura_db_test_fetch_from_write_cache(db, A_TEST_NS, A_TEST_SCHEMA_ID, &key, &rec) == A_DB_REC_NOT_FOUND);
    assert(aura_db_test_fetch_from_write_cache(db, A_TEST_NS, A_TEST_SCHEMA_ID, &key1, &rec1) == A_DB_REC_NOT_FOUND);

    /* DB fetch */
    assert(aura_db_test_fetch_db(db, A_TEST_NS, A_TEST_SCHEMA_ID, &key, &rec) == 0);
    assert(rec.data.len == sizeof("t2_World") - 1);
    assert(strncmp(rec.data.base, "t2_World", data.len) == 0);

    assert(aura_db_test_fetch_db(db, A_TEST_NS, A_TEST_SCHEMA_ID, &key, &rec) == 0);
    assert(rec.data.len == sizeof("t2_World") - 1);
    assert(strncmp(rec.data.base, "t2_World", data.len) == 0);

    aura_db_test_close_with_bg_writer(db);
}

#define A_DB_TEST_TX_TYPE 1

/**
 * Test synchronous group transaction insert fetch delete
 * Transction records makes it to log before user ack
 */
static void a_test_sync_tx_put_get_delete(void) {
    AURA_DBHANDLE db;
    struct aura_iovec key, data;
    struct aura_iovec key1, data1;
    struct aura_iovec key2, data2;
    struct aura_db_rec rec, rec1, rec2;

    db = aura_db_test_open_with_log_writer(
      &mc,
      test_dir,
      O_RDWR,
      A_DB_TEST_WRITE_CACHE_SZ,
      A_DB_TEST_READ_CACHE_SZ,
      A_DB_FILE_MODE);
    assert(db != NULL);

    assert(aura_db_transaction_begin(db, A_DB_TEST_TX_TYPE, 0) == 0);

    key.base = "tx:hello_1";
    key.len = strlen(key.base);
    data.base = "Tx first start data";
    data.len = strlen(data.base);
    assert(aura_db_insert(db, A_TEST_NS, A_TEST_SCHEMA_ID, A_DB_FLAG_NONE, A_DB_INSERT_OP, &key, &data) == 0);

    key1.base = "tx:hello_2";
    key1.len = strlen(key1.base);
    data1.base = "Tx first second data";
    data1.len = strlen(data1.base);
    assert(aura_db_insert(db, A_TEST_NS, A_TEST_SCHEMA_ID, A_DB_FLAG_NONE, A_DB_INSERT_OP, &key1, &data1) == 0);

    key2.base = "tx:hello_3";
    key2.len = strlen(key2.base);
    data2.base = "Tx first last data";
    data2.len = strlen(data2.base);
    assert(aura_db_insert(db, A_TEST_NS, A_TEST_SCHEMA_ID, A_DB_FLAG_NONE, A_DB_INSERT_OP, &key2, &data2) == 0);

    assert(aura_db_transaction_commit(db) == 0);

    /* FETCH */
    assert(aura_db_fetch(db, A_TEST_NS, A_TEST_SCHEMA_ID, &key, &rec) == 0);
    assert(rec.data.len == data.len);
    assert(strncmp(rec.data.base, data.base, data.len) == 0);

    assert(aura_db_fetch(db, A_TEST_NS, A_TEST_SCHEMA_ID, &key1, &rec1) == 0);
    assert(rec1.data.len == data1.len);
    assert(strncmp(rec1.data.base, data1.base, data1.len) == 0);

    assert(aura_db_fetch(db, A_TEST_NS, A_TEST_SCHEMA_ID, &key2, &rec2) == 0);
    assert(rec2.data.len == data2.len);
    assert(strncmp(rec2.data.base, data2.base, data2.len) == 0);

    /* DELETE */
    assert(aura_db_transaction_begin(db, A_DB_TEST_TX_TYPE, 0) == 0);

    assert(aura_db_delete(db, A_TEST_NS, A_TEST_SCHEMA_ID, &key) == 0);
    assert(aura_db_delete(db, A_TEST_NS, A_TEST_SCHEMA_ID, &key1) == 0);
    assert(aura_db_delete(db, A_TEST_NS, A_TEST_SCHEMA_ID, &key2) == 0);

    assert(aura_db_transaction_commit(db) == 0);

    /* FETCH */
    assert(aura_db_fetch(db, A_TEST_NS, A_TEST_SCHEMA_ID, &key, &rec) == A_DB_REC_NOT_FOUND);
    assert(rec.data.base == NULL);
    assert(rec.data.len == 0);

    assert(aura_db_fetch(db, A_TEST_NS, A_TEST_SCHEMA_ID, &key1, &rec1) == A_DB_REC_NOT_FOUND);
    assert(rec1.data.base == NULL);
    assert(rec1.data.len == 0);

    assert(aura_db_fetch(db, A_TEST_NS, A_TEST_SCHEMA_ID, &key2, &rec2) == A_DB_REC_NOT_FOUND);
    assert(rec2.data.base == NULL);
    assert(rec2.data.len == 0);

    aura_db_test_close_with_bg_writer(db);
}

static void a_test_sync_tx_flush_fetch(void) {
    AURA_DBHANDLE db;
    struct aura_iovec key, data;
    struct aura_iovec key1, data1;
    struct aura_iovec key2, data2;
    struct aura_db_rec rec, rec1, rec2;

    db = aura_db_test_open_with_log_writer(
      &mc,
      test_dir,
      O_RDWR,
      A_DB_TEST_WRITE_CACHE_SZ,
      A_DB_TEST_READ_CACHE_SZ,
      A_DB_FILE_MODE);
    assert(db != NULL);

    assert(aura_db_transaction_begin(db, A_DB_TEST_TX_TYPE, 0) == 0);

    key.base = "tx_2:hello_1";
    key.len = strlen(key.base);
    data.base = "Tx_2 first start data";
    data.len = strlen(data.base);
    assert(aura_db_insert(db, A_TEST_NS, A_TEST_SCHEMA_ID, A_DB_FLAG_NONE, A_DB_INSERT_OP, &key, &data) == 0);

    key1.base = "tx_2:hello_2";
    key1.len = strlen(key1.base);
    data1.base = "Tx_2 first second data";
    data1.len = strlen(data1.base);
    assert(aura_db_insert(db, A_TEST_NS, A_TEST_SCHEMA_ID, A_DB_FLAG_NONE, A_DB_INSERT_OP, &key1, &data1) == 0);

    key2.base = "tx_2:hello_3";
    key2.len = strlen(key2.base);
    data2.base = "Tx_2 first last data";
    data2.len = strlen(data2.base);
    assert(aura_db_insert(db, A_TEST_NS, A_TEST_SCHEMA_ID, A_DB_FLAG_NONE, A_DB_INSERT_OP, &key2, &data2) == 0);

    assert(aura_db_transaction_commit(db) == 0);

    /* FETCH cache */
    assert(aura_db_fetch(db, A_TEST_NS, A_TEST_SCHEMA_ID, &key, &rec) == 0);
    assert(rec.data.len == data.len);
    assert(strncmp(rec.data.base, data.base, data.len) == 0);

    assert(aura_db_fetch(db, A_TEST_NS, A_TEST_SCHEMA_ID, &key1, &rec1) == 0);
    assert(rec1.data.len == data1.len);
    assert(strncmp(rec1.data.base, data1.base, data1.len) == 0);

    assert(aura_db_fetch(db, A_TEST_NS, A_TEST_SCHEMA_ID, &key2, &rec2) == 0);
    assert(rec2.data.len == data2.len);
    assert(strncmp(rec2.data.base, data2.base, data2.len) == 0);

    assert(aura_db_test_force_write_cache_flush(db) == 0);
    aura_db_test_write_cache_reset(db);

    /* FETCH cache */
    assert(aura_db_test_fetch_from_write_cache(db, A_TEST_NS, A_TEST_SCHEMA_ID, &key, &rec) == A_DB_REC_NOT_FOUND);
    assert(aura_db_test_fetch_from_write_cache(db, A_TEST_NS, A_TEST_SCHEMA_ID, &key1, &rec1) == A_DB_REC_NOT_FOUND);
    assert(aura_db_test_fetch_from_write_cache(db, A_TEST_NS, A_TEST_SCHEMA_ID, &key2, &rec2) == A_DB_REC_NOT_FOUND);

    /* FETCH db */
    assert(aura_db_test_fetch_db(db, A_TEST_NS, A_TEST_SCHEMA_ID, &key, &rec) == 0);
    assert(rec.data.len == data.len);
    assert(strncmp(rec.data.base, data.base, data.len) == 0);

    assert(aura_db_test_fetch_db(db, A_TEST_NS, A_TEST_SCHEMA_ID, &key1, &rec1) == 0);
    assert(rec1.data.len == data1.len);
    assert(strncmp(rec1.data.base, data1.base, data1.len) == 0);

    assert(aura_db_test_fetch_db(db, A_TEST_NS, A_TEST_SCHEMA_ID, &key2, &rec2) == 0);
    assert(rec2.data.len == data2.len);
    assert(strncmp(rec2.data.base, data2.base, data2.len) == 0);

    aura_db_test_close_with_bg_writer(db);
}

/**
 * @tests:
 * buffer swap
 * auto flushing
 */

int main(int argc, char *argv[]) {
    a_setup_temp_db_files();

    a_test_sync_insert_fetch_delete();
    a_test_sync_tx_put_get_delete();
    a_test_db_flush_fetch();
    a_test_sync_tx_flush_fetch();

    a_cleanup_temp_db_files();
    return 0;
}