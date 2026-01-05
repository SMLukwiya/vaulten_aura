#include "bug_lib.h"
#include "db/db.h"

#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

static char test_dir[256] = {0};

static void a_setup_temp_dir(void) {
    int res;

    snprintf(test_dir, sizeof(test_dir), "/tmp/aura_test_db_%u", getpid());
    res = mkdir(test_dir, S_IRWXU);
    A_BUG_ON_2(false, res != 0);
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
    struct aura_iovec key, data;
    int res;

    snprintf(db_path, sizeof(db_path), "%s/aura.db", test_dir);

    db = aura_db_open(test_dir, db_path, O_RDWR | O_CREAT | O_EXCL | O_TRUNC, A_DB_FILE_MODE);
    assert(db != NULL);

    /* PUT */
    key.base = "fn:hello",
    key.len = sizeof("fn:hello") - 1;
    data.base = "World";
    data.len = sizeof("World") - 1;
    res = aura_db_put_record(db, 1, 1, &key, &data);
    assert(res == 0);

    /* FETCH */
    char buf[32];
    res = aura_db_fetch_record(db, 1, &key, &data);
    assert(res == 0);
    assert(data.len == 5);
    assert(strncmp(data.base, "World", data.len) == 0);

    /* DELETE */
    res = aura_db_delete_record(db, 1, 1, &key);
    assert(res == 0);
    data.base = NULL;
    data.len = 0;
    res = res = aura_db_fetch_record(db, 1, &key, &data);
    assert(res == A_DB_REC_NOT_FOUND);
    assert(data.base == NULL);
    assert(data.len == 0);

    aura_db_close(db);
}

static void a_test_wal_replay(void) {
    AURA_DBHANDLE db;
    char db_path[512];
    int res;
    struct aura_iovec key, data;

    a_setup_temp_dir();
    snprintf(db_path, sizeof(db_path), "%s/aura.db", test_dir);

    db = aura_db_open(test_dir, db_path, O_RDWR | O_CREAT | O_TRUNC, A_DB_FILE_MODE);
    assert(db != NULL);

    /* PUT */
    key.base = "fn:hello",
    key.len = sizeof("fn:hello") - 1;
    data.base = "World";
    data.len = sizeof("World") - 1;
    res = aura_db_put_record(db, 1, 1, &key, &data);
    assert(res == 0);

    aura_db_close(db);

    db = aura_db_open(test_dir, db_path, O_RDWR);
    assert(db != NULL);

    /* FETCH */
    char buf[32];
    res = aura_db_fetch_record(db, 1, &key, &data);
    assert(res == 0);
    assert(data.len == 5);
    assert(strncmp(data.base, "World", data.len) == 0);

    aura_db_close(db);
}

int main(int argc, char *argv[]) {
    a_setup_temp_dir();

    a_test_put_get_delete();
    a_test_wal_replay();

    a_cleanup_temp_dir();
    return 0;
}