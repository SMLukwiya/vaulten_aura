#include "memory_lib.h"
#include "types_lib.h"
#include "url_lib.h"
#include "utils_lib.h"
#include <assert.h>

struct aura_memory_ctx mc;

extern int aura_parse_host_port(struct aura_memory_ctx *mc, char *src, size_t len, struct aura_url *url);

static void a_setup_mc(void) {
    int res;

    aura_memory_ctx_init(&mc);
    res = aura_create_dynamic_slab_alloc_caches(&mc);
    assert(res == 0);
}

static void a_destroy_mc(void) {
    aura_memory_ctx_destroy(&mc);
}

static void a_test_url_normalizing(void) {
    struct aura_iovec normalized_path;
    char *path;

    path = NULL;
    normalized_path = aura_url_path_normalize(&mc, path, 0);
    assert(memcmp(normalized_path.base, a_str_lit_static("/")) == 0);

    path = "/";
    normalized_path = aura_url_path_normalize(NULL, path, strlen(path));
    assert(memcmp(normalized_path.base, a_str_lit_static("/")) == 0);

    path = "/a";
    normalized_path = aura_url_path_normalize(NULL, path, strlen(path));
    assert(memcmp(normalized_path.base, a_str_lit_static("/a")) == 0);

    path = "/aa";
    normalized_path = aura_url_path_normalize(NULL, path, strlen(path));
    assert(memcmp(normalized_path.base, a_str_lit_static("/aa")) == 0);

    path = "/.";
    normalized_path = aura_url_path_normalize(NULL, path, strlen(path));
    assert(memcmp(normalized_path.base, a_str_lit_static("/")) == 0);

    path = "/./";
    normalized_path = aura_url_path_normalize(NULL, path, strlen(path));
    assert(memcmp(normalized_path.base, a_str_lit_static("/")) == 0);

    path = "/..";
    normalized_path = aura_url_path_normalize(NULL, path, strlen(path));
    assert(memcmp(normalized_path.base, a_str_lit_static("/")) == 0);

    path = "/../";
    normalized_path = aura_url_path_normalize(NULL, path, strlen(path));
    assert(memcmp(normalized_path.base, a_str_lit_static("/")) == 0);

    path = "/abc";
    normalized_path = aura_url_path_normalize(NULL, path, strlen(path));
    assert(memcmp(normalized_path.base, a_str_lit_static("/abc")) == 0);

    path = "/abc/../def";
    normalized_path = aura_url_path_normalize(NULL, path, strlen(path));
    assert(memcmp(normalized_path.base, a_str_lit_static("/def")) == 0);

    path = "/abc/../../def";
    normalized_path = aura_url_path_normalize(NULL, path, strlen(path));
    assert(memcmp(normalized_path.base, a_str_lit_static("/def")) == 0);

    path = "/abc/./def";
    normalized_path = aura_url_path_normalize(NULL, path, strlen(path));
    assert(memcmp(normalized_path.base, a_str_lit_static("/abc/def")) == 0);

    path = "/abc/././def";
    normalized_path = aura_url_path_normalize(NULL, path, strlen(path));
    assert(memcmp(normalized_path.base, a_str_lit_static("/abc/def")) == 0);

    path = "/abc/def/ghi/../..";
    normalized_path = aura_url_path_normalize(NULL, path, strlen(path));
    assert(memcmp(normalized_path.base, a_str_lit_static("/abc")) == 0);

    path = "/abc/def/./.";
    normalized_path = aura_url_path_normalize(NULL, path, strlen(path));
    assert(memcmp(normalized_path.base, a_str_lit_static("/abc/def")) == 0);

    path = "/abc/def/ghi/../.";
    normalized_path = aura_url_path_normalize(NULL, path, strlen(path));
    assert(memcmp(normalized_path.base, a_str_lit_static("/abc/def")) == 0);

    path = "/abc/def/./..";
    normalized_path = aura_url_path_normalize(NULL, path, strlen(path));
    assert(memcmp(normalized_path.base, a_str_lit_static("/abc")) == 0);

    path = "/abc/def/..";
    normalized_path = aura_url_path_normalize(NULL, path, strlen(path));
    assert(memcmp(normalized_path.base, a_str_lit_static("/abc")) == 0);

    path = "/abc/def/.";
    normalized_path = aura_url_path_normalize(NULL, path, strlen(path));
    assert(memcmp(normalized_path.base, a_str_lit_static("/abc/def")) == 0);

    path = "/a%62c";
    normalized_path = aura_url_path_normalize(NULL, path, strlen(path));
    assert(memcmp(normalized_path.base, a_str_lit_static("/abc")) == 0);

    path = "/a%6";
    normalized_path = aura_url_path_normalize(NULL, path, strlen(path));
    assert(memcmp(normalized_path.base, a_str_lit_static("/a%6")) == 0);

    path = "/%25";
    normalized_path = aura_url_path_normalize(NULL, path, strlen(path));
    assert(memcmp(normalized_path.base, a_str_lit_static("/%")) == 0);

    path = "/abc//";
    normalized_path = aura_url_path_normalize(NULL, path, strlen(path));
    assert(memcmp(normalized_path.base, a_str_lit_static("/abc//")) == 0);

    path = "/abc//d";
    normalized_path = aura_url_path_normalize(NULL, path, strlen(path));
    assert(memcmp(normalized_path.base, a_str_lit_static("/abc//d")) == 0);

    path = "//";
    normalized_path = aura_url_path_normalize(NULL, path, strlen(path));
    assert(memcmp(normalized_path.base, a_str_lit_static("//")) == 0);

    path = "//abc";
    normalized_path = aura_url_path_normalize(NULL, path, strlen(path));
    assert(memcmp(normalized_path.base, a_str_lit_static("//abc")) == 0);
}

static void a_test_host_port(void) {
    struct aura_url url;
    char *src;
    int res;

    src = "127.0.0.1";
    res = aura_parse_host_port(&mc, src, strlen(src), &url);
    assert(res != -1);
    assert(memcmp(url.authority.host.base, a_str_lit_static("127.0.0.1")) == 0);
    assert(url.authority.port == 0);

    src = "127.0.0.1/";
    res = aura_parse_host_port(&mc, src, strlen(src), &url);
    assert(res != -1);
    assert(memcmp(url.authority.host.base, a_str_lit_static("127.0.0.1")) == 0);
    assert(url.authority.port == 0);

    src = "127.0.0.1?";
    res = aura_parse_host_port(&mc, src, strlen(src), &url);
    assert(res != -1);
    assert(memcmp(url.authority.host.base, a_str_lit_static("127.0.0.1")) == 0);
    assert(url.authority.port == 0);

    src = "127.0.0.1:8081/";
    res = aura_parse_host_port(&mc, src, strlen(src), &url);
    assert(res != -1);
    assert(memcmp(url.authority.host.base, a_str_lit_static("127.0.0.1")) == 0);
    assert(url.authority.port == 8081);

    src = "127.0.0.1:8081?";
    res = aura_parse_host_port(&mc, src, strlen(src), &url);
    assert(res != -1);
    assert(memcmp(url.authority.host.base, a_str_lit_static("127.0.0.1")) == 0);
    assert(url.authority.port == 8081);

    src = "[::ffff:192.0.2.1]:8081/";
    res = aura_parse_host_port(&mc, src, strlen(src), &url);
    assert(res != -1);
    assert(memcmp(url.authority.host.base, a_str_lit_static("::ffff:192.0.2.1")) == 0);
    assert(url.authority.port == 8081);

    src = "[::ffff:192.0.2.1]:8081?";
    res = aura_parse_host_port(&mc, src, strlen(src), &url);
    assert(res != -1);
    assert(memcmp(url.authority.host.base, a_str_lit_static("::ffff:192.0.2.1")) == 0);
    assert(url.authority.port == 8081);

    src = "[::ffff:192.0.2.1:8081/";
    res = aura_parse_host_port(&mc, src, strlen(src), &url);
    assert(res == -1);

    src = ":8081/";
    res = aura_parse_host_port(&mc, src, strlen(src), &url);
    assert(res == -1);

    src = "[]:8081/";
    res = aura_parse_host_port(&mc, src, strlen(src), &url);
    assert(res == -1);
}

static void a_test_url_parse(void) {
    struct aura_url parsed_url;
    char *url;
    int res;

    url = "http://example.com/abc";
    res = aura_url_parse(&mc, url, strlen(url), &parsed_url);
    assert(res == 0);
    assert(parsed_url.scheme == 1);
    assert(memcmp(parsed_url.authority.host.base, a_str_lit_static("example.com")) == 0);
    assert(parsed_url.authority.port == 0);
    assert(aura_url_get_default_port(&parsed_url) == 80);
    assert(memcmp(parsed_url.path.base, a_str_lit_static("/abc")) == 0);
    assert(parsed_url.query.base == NULL);

    url = "http://example.com";
    res = aura_url_parse(&mc, url, strlen(url), &parsed_url);
    assert(res == 0);
    assert(parsed_url.scheme == 1);
    assert(memcmp(parsed_url.authority.host.base, a_str_lit_static("example.com")) == 0);
    assert(parsed_url.authority.port == 0);
    assert(aura_url_get_default_port(&parsed_url) == 80);
    assert(memcmp(parsed_url.path.base, a_str_lit_static("/")) == 0);
    assert(parsed_url.query.base == NULL);

    url = "http://example.com:81/abc";
    res = aura_url_parse(&mc, url, strlen(url), &parsed_url);
    assert(res == 0);
    assert(parsed_url.scheme == 1);
    assert(memcmp(parsed_url.authority.host.base, a_str_lit_static("example.com")) == 0);
    assert(parsed_url.authority.port == 81);
    assert(aura_url_get_default_port(&parsed_url) == 81);
    assert(memcmp(parsed_url.path.base, a_str_lit_static("/abc")) == 0);
    assert(parsed_url.query.base == NULL);

    url = "http://example.com:81";
    res = aura_url_parse(&mc, url, strlen(url), &parsed_url);
    assert(res == 0);
    assert(parsed_url.scheme == 1);
    assert(memcmp(parsed_url.authority.host.base, a_str_lit_static("example.com")) == 0);
    assert(parsed_url.authority.port == 81);
    assert(aura_url_get_default_port(&parsed_url) == 81);
    assert(memcmp(parsed_url.path.base, a_str_lit_static("/")) == 0);
    assert(parsed_url.query.base == NULL);

    url = "https://example.com/abc";
    res = aura_url_parse(&mc, url, strlen(url), &parsed_url);
    assert(res == 0);
    assert(parsed_url.scheme == 2);
    assert(memcmp(parsed_url.authority.host.base, a_str_lit_static("example.com")) == 0);
    assert(parsed_url.authority.port == 0);
    assert(aura_url_get_default_port(&parsed_url) == 443);
    assert(memcmp(parsed_url.path.base, a_str_lit_static("/abc")) == 0);
    assert(parsed_url.query.base == NULL);

    url = "http:/abc";
    res = aura_url_parse(&mc, url, strlen(url), &parsed_url);
    assert(res != 0);

    url = "ftp://example.com/abc";
    res = aura_url_parse(&mc, url, strlen(url), &parsed_url);
    assert(res != 0);

    url = "http://abc:234123/abc";
    res = aura_url_parse(&mc, url, strlen(url), &parsed_url);
    assert(res != 0);

    url = "http://[::ffff:192.0.2.128]";
    res = aura_url_parse(&mc, url, strlen(url), &parsed_url);
    assert(res == 0);
    assert(parsed_url.scheme == 1);
    assert(memcmp(parsed_url.authority.host.base, a_str_lit_static("::ffff:192.0.2.128")) == 0);
    assert(parsed_url.authority.port == 0);
    assert(aura_url_get_default_port(&parsed_url) == 80);
    assert(memcmp(parsed_url.path.base, a_str_lit_static("/")) == 0);
    assert(parsed_url.query.base == NULL);

    url = "https://[::ffff:192.0.2.128]/abc";
    res = aura_url_parse(&mc, url, strlen(url), &parsed_url);
    assert(res == 0);
    assert(parsed_url.scheme == 2);
    assert(memcmp(parsed_url.authority.host.base, a_str_lit_static("::ffff:192.0.2.128")) == 0);
    assert(parsed_url.authority.port == 0);
    assert(aura_url_get_default_port(&parsed_url) == 443);
    assert(memcmp(parsed_url.path.base, a_str_lit_static("/abc")) == 0);
    assert(parsed_url.query.base == NULL);

    url = "https://[::ffff:192.0.2.128]:111/abc";
    res = aura_url_parse(&mc, url, strlen(url), &parsed_url);
    assert(res == 0);
    assert(parsed_url.scheme == 2);
    assert(memcmp(parsed_url.authority.host.base, a_str_lit_static("::ffff:192.0.2.128")) == 0);
    assert(parsed_url.authority.port == 111);
    assert(aura_url_get_default_port(&parsed_url) == 111);
    assert(memcmp(parsed_url.path.base, a_str_lit_static("/abc")) == 0);
    assert(parsed_url.query.base == NULL);

    url = "http://example.com:8080?abc";
    res = aura_url_parse(&mc, url, strlen(url), &parsed_url);
    assert(res == 0);
    assert(memcmp(parsed_url.path.base, a_str_lit_static("/")) == 0);
    assert(memcmp(parsed_url.query.base, a_str_lit_static("abc")) == 0);
}

int main(int argc, char *argv[]) {
    a_setup_mc();
    a_test_url_normalizing();
    a_test_url_parse();
    a_test_host_port();

    a_destroy_mc();
    return 0;
}