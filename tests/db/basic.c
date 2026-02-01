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
    ssize_t res;

    snprintf(db_path, sizeof(db_path), "%s/aura.db", test_dir);

    db = aura_db_open(NULL, test_dir, db_path, O_RDWR | O_CREAT | O_EXCL | O_TRUNC, A_DB_FILE_MODE);
    assert(db != NULL);

    /* PUT */
    key.base = "fn:hello_1",
    key.len = strlen(key.base);
    data.base = "World";
    data.len = strlen(data.base);
    res = aura_db_record_insert(db, 1, 1, A_DB_JOB_ID_NONE, A_DB_PREV_JOB_REC_NONE, A_DB_OP_INSERT, &key, &data, A_DB_EXEC_DIRECT, NULL);
    assert(res > 0);

    key1.base = "fn:hello_2",
    key1.len = strlen(key1.base);
    data1.base = "World_2";
    data1.len = strlen(data1.base);
    res = aura_db_record_insert(db, 1, 1, A_DB_JOB_ID_NONE, A_DB_PREV_JOB_REC_NONE, A_DB_OP_INSERT, &key1, &data1, A_DB_EXEC_DIRECT, NULL);
    assert(res > 0);

    /* FETCH */
    res = aura_db_record_fetch(db, 1, 1, &key, &data);
    assert(res == 0);
    assert(data.len == sizeof("World") - 1);
    assert(strncmp(data.base, "World", data.len) == 0);

    res = aura_db_record_fetch(db, 1, 1, &key1, &data1);
    assert(res == 0);
    assert(data1.len == sizeof("World_2") - 1);
    assert(strncmp(data1.base, "World_2", data1.len) == 0);

    /* DELETE */
    res = aura_db_record_delete(db, 1, 1, 0, &key, A_DB_EXEC_DIRECT, NULL);
    assert(res == 0);
    res = aura_db_record_delete(db, 1, 1, 0, &key1, A_DB_EXEC_DIRECT, NULL);
    assert(res == 0);

    /* FETCH AGAIN */
    res = res = aura_db_record_fetch(db, 1, 1, &key, &data);
    assert(res == A_DB_REC_NOT_FOUND);
    assert(data.base == NULL);
    assert(data.len == 0);

    res = res = aura_db_record_fetch(db, 1, 1, &key1, &data1);
    assert(res == A_DB_REC_NOT_FOUND);
    assert(data1.base == NULL);
    assert(data1.len == 0);

    aura_db_close(db);
}

static void a_test_job_insert_update_delete(void) {
    AURA_DBHANDLE *db;
    char db_path[512];
    int res;
    uint64_t job_id;
    struct aura_db_job_rec *job;

    snprintf(db_path, sizeof(db_path), "%s/aura.db", test_dir);

    db = aura_db_open(NULL, test_dir, db_path, O_RDWR | O_CREAT | O_EXCL | O_TRUNC, A_DB_FILE_MODE);
    assert(db != NULL);

    /* PUT */
    job_id = aura_db_job_insert(db, A_DB_JOB_OP_CREATE, A_DB_JOB_START, 0, 0, A_DB_EXEC_DIRECT, NULL);
    assert(job_id > 0);

    /* FETCH */
    job = aura_db_job_fetch(db, job_id);
    assert(job != NULL);
    assert(job->job_type == A_DB_JOB_OP_CREATE);
    assert(job->state == A_DB_JOB_START);

    /* UPDATE */
    res = aura_db_job_update(db, job->job_id, A_DB_JOB_FAILED, 1, 0, A_DB_EXEC_DIRECT, NULL);
    assert(res == 0);

    /* FETCH */
    job = aura_db_job_fetch(db, job_id);
    assert(job != NULL);
    assert(job->job_type == A_DB_JOB_OP_CREATE);
    assert(job->state == A_DB_JOB_FAILED);
    assert(job->error_code == 1);
    assert(job->last_rec_off == 0);

    aura_db_close(db);
}

static void a_test_job_step_insert_update_delete(void) {
    AURA_DBHANDLE db;
    struct aura_db_job_rec *job;
    struct aura_db_job_step_rec *job_step;
    struct aura_iovec key;
    char db_path[512];
    uint64_t job_id;
    int res;

    snprintf(db_path, sizeof(db_path), "%s/aura.db", test_dir);

    db = aura_db_open(NULL, test_dir, db_path, O_RDWR | O_CREAT | O_EXCL | O_TRUNC, A_DB_FILE_MODE);
    assert(db != NULL);

    key.base = "fn:job_step:v1";
    key.len = strlen(key.base);
    job_id = aura_db_job_insert(db, A_DB_JOB_OP_CREATE, A_DB_JOB_START, 0, 0, A_DB_EXEC_DIRECT, NULL);
    assert(job_id > 0);

    /*PUT */
    res = aura_db_job_step_insert(db, job_id, A_DB_JOB_OP_CREATE, 1, &key, A_DB_EXEC_DIRECT, NULL);
    assert(res == 0);

    /* FETCH */
    job_step = aura_db_job_step_fetch(db, A_DB_JOB_OP_CREATE, &key);
    assert(job_step != NULL);
    assert(job_step->job_id == job_id);
    assert(job_step->job_type == A_DB_JOB_OP_CREATE);
    assert(job_step->step == 1);

    /* UPDATE */
    res = aura_db_job_step_insert(db, job_id, A_DB_JOB_OP_CREATE, 2, &key, A_DB_EXEC_DIRECT, NULL);
    assert(res == 0);

    job_step = aura_db_job_step_fetch(db, A_DB_JOB_OP_CREATE, &key);
    assert(job_step != NULL);
    assert(job_step->job_id == job_id);
    assert(job_step->job_type == A_DB_JOB_OP_CREATE);
    assert(job_step->step == 2);

    aura_db_close(db);
}

extern int aura_db_force_wal_replay(AURA_DBHANDLE _db);
extern int aura_db_clear_record_cache(AURA_DBHANDLE _db);

static void a_test_wal_replay(void) {
    AURA_DBHANDLE db;
    char db_path[512];
    ssize_t res;
    struct aura_iovec key, data, key1, data1, key2, data2, key3, data3, key4, data4, key5, data5;
    uint64_t job_id;
    off_t prev_job_rec;

    snprintf(db_path, sizeof(db_path), "%s/aura.db", test_dir);

    db = aura_db_open(NULL, test_dir, db_path, O_RDWR | O_CREAT | O_TRUNC, A_DB_FILE_MODE);
    assert(db != NULL);

    /* PUT */
    /* Insert record not associated with job id */
    key.base = "fn:wizzy_replay_1",
    key.len = sizeof("fn:wizzy_replay_1") - 1;
    data.base = "Shizzy World_1";
    data.len = sizeof("Shizzy World_1") - 1;
    res = aura_db_record_insert(db, 1, 1, A_DB_JOB_ID_NONE, A_DB_PREV_JOB_REC_NONE, A_DB_OP_INSERT, &key, &data, A_DB_EXEC_DIRECT, NULL);
    assert(res > 0);

    /* Create job one */
    job_id = aura_db_job_insert(db, A_DB_JOB_OP_CREATE, A_DB_JOB_START, 0, 0, A_DB_EXEC_DIRECT, NULL);
    assert(job_id > 0);

    /* First record under job one */
    prev_job_rec = 0;
    key1.base = "fn:replay_1",
    key1.len = sizeof("fn:replay_1") - 1;
    data1.base = "Job one first associated record";
    data1.len = sizeof("Job one first associated record") - 1;
    res = aura_db_record_insert(db, 1, 1, job_id, prev_job_rec, A_DB_OP_INSERT, &key1, &data1, A_DB_EXEC_DIRECT, NULL);
    assert(res > 0);
    prev_job_rec = res;

    /* Fail this job */
    res = aura_db_job_update(db, job_id, A_DB_JOB_FAILED, 1, prev_job_rec, A_DB_EXEC_DIRECT, NULL);

    /* Create job two */
    job_id = aura_db_job_insert(db, A_DB_JOB_OP_CREATE, A_DB_JOB_START, 0, 0, A_DB_EXEC_DIRECT, NULL);
    assert(job_id > 0);

    /* First record under job two */
    prev_job_rec = 0;
    key2.base = "fn:replay_2",
    key2.len = sizeof("fn:replay_2") - 1;
    data2.base = "Job two first associated record";
    data2.len = sizeof("Job two first associated record") - 1;
    res = aura_db_record_insert(db, 1, 1, job_id, prev_job_rec, A_DB_OP_INSERT, &key2, &data2, A_DB_EXEC_DIRECT, NULL);
    assert(res > 0);

    /* Second record under job two */
    prev_job_rec = res;
    key3.base = "fn:replay_3",
    key3.len = sizeof("fn:replay_3") - 1;
    data3.base = "Job two second associated record";
    data3.len = sizeof("Job two second associated record") - 1;
    res = aura_db_record_insert(db, 1, 1, job_id, prev_job_rec, A_DB_OP_INSERT, &key3, &data3, A_DB_EXEC_DIRECT, NULL);
    assert(res > 0);

    /* Commit job */
    prev_job_rec = res;
    res = aura_db_job_update(db, job_id, A_DB_JOB_DONE, 0, prev_job_rec, A_DB_EXEC_DIRECT, NULL);

    /* Create job three */
    job_id = aura_db_job_insert(db, A_DB_JOB_OP_CREATE, A_DB_JOB_START, 0, 0, A_DB_EXEC_DIRECT, NULL);
    assert(job_id > 0);

    /* First record under job three */
    prev_job_rec = 0;
    key4.base = "fn:replay_4",
    key4.len = sizeof("fn:replay_4") - 1;
    data4.base = "Job three first associated record";
    data4.len = sizeof("Job three first associated record") - 1;
    res = aura_db_record_insert(db, 1, 1, job_id, prev_job_rec, A_DB_OP_INSERT, &key4, &data4, A_DB_EXEC_DIRECT, NULL);
    assert(res > 0);

    /**
     * Leave job three as pending and force a replay
     * Clean cache to force fetches from DB
     */
    aura_db_force_wal_replay(db);
    aura_db_clear_record_cache(db);

    /* First record with no job id */
    res = aura_db_record_fetch(db, 1, 1, &key, &data);
    assert(res == 0);
    assert(data.len == sizeof("Shizzy World_1") - 1);
    assert(strncmp(data.base, "Shizzy World_1", data.len) == 0);

    /* Fetch first record of job one: Job failed */
    res = aura_db_record_fetch(db, 1, 1, &key1, &data1);
    assert(res == A_DB_REC_NOT_FOUND);

    /* Fetch second job recodes, job succeeded */
    data2.base = NULL;
    res = aura_db_record_fetch(db, 1, 1, &key2, &data2);
    assert(res == 0);
    assert(data2.len == sizeof("Job two first associated record") - 1);
    assert(strncmp(data2.base, "Job two first associated record", data2.len) == 0);

    data3.base = NULL;
    res = aura_db_record_fetch(db, 1, 1, &key3, &data3);
    assert(res == 0);
    assert(data3.len == sizeof("Job two second associated record") - 1);
    assert(strncmp(data3.base, "Job two second associated record", data3.len) == 0);

    /* Third job record (job pending) */
    res = aura_db_record_fetch(db, 1, 1, &key4, &data4);
    assert(res == A_DB_REC_NOT_FOUND);

    /* Add second record for job three */
    key5.base = "fn:replay_5";
    key5.len = sizeof("fn:deploy_5") - 1;
    data5.base = "Job three second associated record";
    data5.len = sizeof("Job three second associated record") - 1;
    res = aura_db_record_insert(db, 1, 1, job_id, 0, A_DB_OP_INSERT, &key5, &data5, A_DB_EXEC_DIRECT, NULL);
    assert(res > 0);

    /* Pass job three */
    res = aura_db_job_update(db, job_id, A_DB_JOB_DONE, 0, 0, A_DB_EXEC_DIRECT, NULL);
    assert(res == 0);

    aura_db_force_wal_replay(db);
    aura_db_clear_record_cache(db);

    /* Fetch job three records */
    data4.base = NULL;
    res = aura_db_record_fetch(db, 1, 1, &key4, &data4);
    assert(res == 0);
    assert(data4.len == sizeof("Job three first associated record") - 1);
    assert(strncmp(data4.base, "Job three first associated record", data4.len) == 0);

    data5.base = NULL;
    res = aura_db_record_fetch(db, 1, 1, &key5, &data5);
    assert(res == 0);
    assert(data5.len == sizeof("Job three second associated record") - 1);
    assert(strncmp(data5.base, "Job three second associated record", data5.len) == 0);

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
    uint64_t record_cnt, new_record_cnt;

    snprintf(db_path, sizeof(db_path), "%s/aura.db", test_dir);

    db = aura_db_open(NULL, test_dir, db_path, O_RDWR | O_CREAT | O_TRUNC, A_DB_FILE_MODE);
    assert(db != NULL);

    old_file_size = aura_db_get_size(db);
    record_cnt = aura_db_get_record_cnt(db);

    /* PUT */
    key.base = "fn:hello_4",
    key.len = sizeof("fn:hello_4") - 1;
    data.base = "World_4";
    data.len = sizeof("World_4") - 1;
    res = aura_db_record_insert(db, 1, 1, A_DB_JOB_ID_NONE, A_DB_PREV_JOB_REC_NONE, A_DB_OP_INSERT, &key, &data, A_DB_EXEC_DIRECT, NULL);
    assert(res == 0);

    key1.base = "fn:doom",
    key1.len = sizeof("fn:doom") - 1;
    data1.base = "DoomsWorld";
    data1.len = sizeof("DoomsWorld") - 1;
    res = aura_db_record_insert(db, 1, 1, A_DB_JOB_ID_NONE, A_DB_PREV_JOB_REC_NONE, A_DB_OP_INSERT, &key1, &data1, A_DB_EXEC_DIRECT, NULL);
    assert(res == 0);

    /* DELETE */
    res = aura_db_record_delete(db, 1, 1, 0, &key, A_DB_EXEC_DIRECT, NULL);
    assert(res == 0);
    res = aura_db_record_delete(db, 1, 1, 0, &key1, A_DB_EXEC_DIRECT, NULL);
    assert(res == 0);

    aura_db_force_wal_replay(db);
    aura_db_force_compact(db);

    new_file_size = aura_db_get_size(db);
    assert(old_file_size == new_file_size);
    new_record_cnt = aura_db_get_record_cnt(db);
    assert(record_cnt == new_record_cnt);

    /* FETCH */
    res = aura_db_record_fetch(db, 1, 1, &key, &data);
    assert(res == A_DB_REC_NOT_FOUND);
    assert(data.len == 0);
    assert(data.base == NULL);

    res = aura_db_record_fetch(db, 1, 1, &key1, &data);
    assert(res == A_DB_REC_NOT_FOUND);
    assert(data.len == 0);
    assert(data.base == NULL);

    aura_db_close(db);
}

int main(int argc, char *argv[]) {
    a_setup_temp_dir();

    a_test_put_get_delete();
    a_test_job_insert_update_delete();
    a_test_job_step_insert_update_delete();
    a_test_wal_replay();
    // a_test_db_compaction();

    a_cleanup_temp_dir();
    return 0;
}