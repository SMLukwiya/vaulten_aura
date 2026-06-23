#include "hashmap/map.h"
#include "mem.h"
#include "string_lib.h"
#include <assert.h>

struct aura_mem_ctx mc;

static void a_setup_mc(void) {
    int res;

    aura_mem_ctx_init(&mc);
    assert(aura_create_dynamic_slab_alloc_caches(&mc) == 0);
}

static void a_destroy_mc(void) {
    aura_mem_ctx_destroy(&mc);
}

static void a_test_hashmap_put_get_delete() {
    struct aura_rh_map map;
    void *data;

    assert(aura_rh_map_init(&map, &mc, 10, A_RH_KEY_U64, true) == 0);

    struct aura_rh_map_key num_key1, num_key2, num_key3;
    const char *num_data1 = "Num key value one";
    aura_rh_map_key_init(&num_key1, 65536, sizeof(uint64_t), A_RH_KEY_U64);

    const char *num_data2 = "Num key value two";
    aura_rh_map_key_init(&num_key2, 62386, sizeof(uint64_t), A_RH_KEY_U64);

    const char *num_data3 = "Num key value three";
    aura_rh_map_key_init(&num_key3, 65432123, sizeof(uint64_t), A_RH_KEY_U64);

    /* Insert */
    assert(aura_rh_map_put(&map, &num_key1, (void *)num_data1) == 0);

    assert(aura_rh_map_put(&map, &num_key2, (void *)num_data2) == 0);

    /* Get */
    data = aura_rh_map_get(&map, &num_key1);
    assert(data != NULL);
    assert(strcmp((char *)data, num_data1) == 0);

    data = aura_rh_map_get(&map, &num_key2);
    assert(data != NULL);
    assert(strcmp((char *)data, num_data2) == 0);

    /* Delete */
    aura_rh_map_del(&map, &num_key1, &data);
    assert(data != NULL);
    assert(strcmp((char *)data, num_data1) == 0);

    assert(aura_rh_map_put(&map, &num_key3, (void *)num_data3) == 0);

    aura_rh_map_del(&map, &num_key2, &data);
    assert(data != NULL);
    assert(strcmp((char *)data, num_data2) == 0);

    data = aura_rh_map_get(&map, &num_key3);
    assert(data != NULL);
    assert(strcmp((char *)data, num_data3) == 0);

    data = aura_rh_map_get(&map, &num_key1);
    assert(data == NULL);

    aura_rh_map_del(&map, &num_key3, &data);
    assert(data != NULL);
    assert(strcmp((char *)data, num_data3) == 0);

    data = aura_rh_map_get(&map, &num_key2);
    assert(data == NULL);

    data = aura_rh_map_get(&map, &num_key3);
    assert(data == NULL);

    /* Get with Empty key */
    aura_rh_map_key_init(&num_key1, A_RH_KEY_EMPTY, sizeof(uint64_t), A_RH_KEY_U64);
    assert(aura_rh_map_put(&map, &num_key1, NULL) < 0);

    /* Get Non existent key */
    aura_rh_map_key_init(&num_key1, 12345, sizeof(uint64_t), A_RH_KEY_U64);
    data = aura_rh_map_get(&map, &num_key1);
    assert(data == NULL);

    aura_rh_map_destroy(&map);

    /* String Map */
    assert(aura_rh_map_init(&map, &mc, 10, A_RH_KEY_STR, true) == 0);

    struct aura_rh_map_key s_key1, s_key2, s_key3;

    const char *str_data1 = "Key str data one";
    aura_rh_map_key_init(&s_key1, (uint64_t)("key str1"), sizeof("key str1") - 1, A_RH_KEY_STR);

    const char *str_data2 = "Key str data two";
    aura_rh_map_key_init(&s_key2, (uint64_t)("key str2"), sizeof("key str2") - 1, A_RH_KEY_STR);

    const char *str_data3 = "Key str data three";
    aura_rh_map_key_init(&s_key3, (uint64_t)("key str3"), sizeof("key str3") - 1, A_RH_KEY_STR);

    /* Insert */
    assert(aura_rh_map_put(&map, &s_key1, (void *)str_data1) == 0);

    assert(aura_rh_map_put(&map, &s_key2, (void *)str_data2) == 0);

    /* Get */
    data = aura_rh_map_get(&map, &s_key1);
    assert(data != NULL);
    assert(strcmp((char *)data, str_data1) == 0);

    data = aura_rh_map_get(&map, &s_key2);
    assert(data != NULL);
    assert(strcmp((char *)data, str_data2) == 0);

    /* Delete */
    aura_rh_map_del(&map, &s_key1, &data);
    assert(data != NULL);
    assert(strcmp((char *)data, str_data1) == 0);

    assert(aura_rh_map_put(&map, &s_key3, (void *)str_data3) == 0);

    aura_rh_map_del(&map, &s_key2, &data);
    assert(data != NULL);
    assert(strcmp((char *)data, str_data2) == 0);

    data = aura_rh_map_get(&map, &s_key3);
    assert(data != NULL);
    assert(strcmp((char *)data, str_data3) == 0);

    data = aura_rh_map_get(&map, &s_key1);
    assert(data == NULL);

    aura_rh_map_del(&map, &s_key3, &data);
    assert(data != NULL);
    assert(strcmp((char *)data, str_data3) == 0);

    data = aura_rh_map_get(&map, &s_key3);
    assert(data == NULL);

    data = aura_rh_map_get(&map, &s_key2);
    assert(data == NULL);

    /* Get with Empty key */
    aura_rh_map_key_init(&s_key1, (uint64_t)NULL, 0, A_RH_KEY_STR);
    assert(aura_rh_map_put(&map, &s_key1, NULL) < 0);

    /* Get Non existent key */
    const char *non_key = "non-key";
    aura_rh_map_key_init(&s_key1, (uint64_t)non_key, strlen(non_key) - 1, A_RH_KEY_STR);
    data = aura_rh_map_get(&map, &s_key1);
    assert(data == NULL);

    aura_rh_map_destroy(&map);
}

int main(int argc, char **argv) {
    a_setup_mc();
    a_test_hashmap_put_get_delete();
    a_destroy_mc();
    return 0;
}