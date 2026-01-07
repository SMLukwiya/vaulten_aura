#include "db/db.h"

#include <assert.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

static char test_dir[256] = {0};

static void a_setup_temp_dir(void) {
    int res;

    snprintf(test_dir, sizeof(test_dir), "/tmp/aura_test_db_%u", getpid());
    res = mkdir(test_dir, S_IRWXU);
    assert(res == 0);
}

static void a_cleanup_temp_dir(void) {
    int res;
    char cmd[512];

    snprintf(cmd, sizeof(cmd), "rm -rf %s", test_dir);
    system(cmd);
}

static void a_test_put_get_delete(void) {
    AURA_DBHANDLE *db;
    char db_path[512];
    struct aura_iovec key, key1, data, data1;
    int res;

    snprintf(db_path, sizeof(db_path), "%s/aura.db", test_dir);

    db = aura_db_open(test_dir, db_path, O_RDWR | O_CREAT | O_EXCL | O_TRUNC, A_DB_FILE_MODE);
    assert(db != NULL);

    /* PUT */
    key.base = "fn:hello_1",
    key.len = sizeof("fn:hello_1") - 1;
    data.base = "World";
    data.len = sizeof("World") - 1;
    res = aura_db_put_record(db, 1, 1, &key, &data);
    assert(res == 0);

    key1.base = "fn:hello_2",
    key1.len = sizeof("fn:hello_2") - 1;
    data1.base = "World_2";
    data1.len = sizeof("World_2") - 1;
    res = aura_db_put_record(db, 1, 1, &key1, &data1);
    assert(res == 0);

    /* FETCH */
    res = aura_db_fetch_record(db, 1, &key, &data);
    assert(res == 0);
    assert(data.len == sizeof("World") - 1);
    assert(strncmp(data.base, "World", data.len) == 0);

    res = aura_db_fetch_record(db, 1, &key1, &data1);
    assert(res == 0);
    assert(data1.len == sizeof("World_2") - 1);
    assert(strncmp(data1.base, "World_2", data1.len) == 0);

    /* DELETE */
    res = aura_db_delete_record(db, 1, 1, &key);
    assert(res == 0);
    res = aura_db_delete_record(db, 1, 1, &key1);
    assert(res == 0);

    /* FETCH AGAIN */
    res = res = aura_db_fetch_record(db, 1, &key, &data);
    assert(res == A_DB_REC_NOT_FOUND);
    assert(data.base == NULL);
    assert(data.len == 0);

    res = res = aura_db_fetch_record(db, 1, &key1, &data1);
    assert(res == A_DB_REC_NOT_FOUND);
    assert(data1.base == NULL);
    assert(data1.len == 0);

    aura_db_close(db);
}

extern int aura_db_force_wal_replay(AURA_DBHANDLE _db);
extern int aura_db_clear_record_cache(AURA_DBHANDLE _db);

static void a_test_wal_replay(void) {
    AURA_DBHANDLE db;
    char db_path[512];
    int res;
    struct aura_iovec key, data;

    snprintf(db_path, sizeof(db_path), "%s/aura.db", test_dir);

    db = aura_db_open(test_dir, db_path, O_RDWR | O_CREAT | O_TRUNC, A_DB_FILE_MODE);
    assert(db != NULL);

    /* PUT */
    key.base = "fn:hello_3",
    key.len = sizeof("fn:hello_3") - 1;
    data.base = "World_3";
    data.len = sizeof("World_3") - 1;
    res = aura_db_put_record(db, 1, 1, &key, &data);
    assert(res == 0);

    aura_db_force_wal_replay(db);
    aura_db_clear_record_cache(db);

    /* Fetch should be read from disk here */
    res = aura_db_fetch_record(db, 1, &key, &data);
    assert(res == 0);
    assert(data.len == sizeof("World_3") - 1);
    assert(strncmp(data.base, "World_3", data.len) == 0);

    /* DELETE */
    res = aura_db_delete_record(db, 1, 1, &key);
    assert(res == 0);

    aura_db_close(db);
}

extern int aura_db_force_compact(AURA_DBHANDLE db);

static void a_test_db_compaction(void) {
    AURA_DBHANDLE db;
    char db_path[512];
    struct aura_iovec key, key1, data, data1;
    int res;
    struct stat statbuf;
    size_t old_file_size, new_file_size;

    snprintf(db_path, sizeof(db_path), "%s/aura.db", test_dir);

    db = aura_db_open(test_dir, db_path, O_RDWR | O_CREAT | O_TRUNC, A_DB_FILE_MODE);
    assert(db != NULL);

    old_file_size = aura_db_get_size(db);

    /* PUT */
    key.base = "fn:hello_4",
    key.len = sizeof("fn:hello_4") - 1;
    data.base = "World_4";
    data.len = sizeof("World_4") - 1;
    res = aura_db_put_record(db, 1, 1, &key, &data);
    assert(res == 0);

    key1.base = "fn:doom",
    key1.len = sizeof("fn:doom") - 1;
    data1.base = "DoomsWorld";
    data1.len = sizeof("DoomsWorld") - 1;
    res = aura_db_put_record(db, 1, 1, &key1, &data1);
    assert(res == 0);

    /* DELETE */
    res = aura_db_delete_record(db, 1, 1, &key);
    assert(res == 0);
    res = aura_db_delete_record(db, 1, 1, &key1);
    assert(res == 0);

    aura_db_force_wal_replay(db);
    aura_db_force_compact(db);

    new_file_size = aura_db_get_size(db);
    assert(old_file_size == new_file_size);

    /* FETCH */
    res = aura_db_fetch_record(db, 1, &key, &data);
    assert(res == A_DB_REC_NOT_FOUND);
    assert(data.len == 0);
    assert(data.base == NULL);

    res = aura_db_fetch_record(db, 1, &key1, &data);
    assert(res == A_DB_REC_NOT_FOUND);
    assert(data.len == 0);
    assert(data.base == NULL);

    aura_db_close(db);
}

int main(int argc, char *argv[]) {
    a_setup_temp_dir();

    a_test_put_get_delete();
    a_test_wal_replay();
    a_test_db_compaction();

    a_cleanup_temp_dir();
    return 0;
}