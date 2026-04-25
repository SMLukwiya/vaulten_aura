#include "url_lib.h"
#include "error_lib.h"
#include <string_lib.h>

static inline int a_decode_hex(int8_t c) {
    if ('0' <= c && c <= '9')
        return c - '0';
    else if ('A' <= c && c <= 'F')
        return c - 'A' + 0xa;
    else if ('a' <= c && c <= 'f')
        return c - 'a' + 0xa;
    return -1;
}

static inline int a_url_find_prev_slash(char *path, size_t len) {
    for (int i = len; i >= 0; --i)
        if (path[i] == '/')
            return i;

    return 0;
}

struct aura_iovec aura_url_path_normalize(struct aura_memory_ctx *mc, char *path, size_t len) {
    char *src, *dest;
    struct aura_iovec normalized_path;
    size_t off, dest_off, prev_slash;

    normalized_path.base = NULL;
    normalized_path.len = 0;

    if (path && *path != '/') {
        /* rebuild */
    }

    src = path;

    dest = aura_alloc(mc, len);
    if (!dest && len > 0)
        return normalized_path;

    off = dest_off = prev_slash = 0;
    while (off < len) {
        int hi, lo;
        char decoded;

        if (src[off] == '%' && (off + 2 < len)) {
            if ((hi = a_decode_hex(src[off + 1])) > 0 && (lo = a_decode_hex(src[off + 2])) > 0) {
                decoded = (hi << 4) | lo;
                off += 3;
            } else {
                decoded = src[off++];
            }
        } else {
            decoded = src[off++];
        }

        if (decoded == '/') {
            /* "/.." */
            if (off + 1 < len && src[off] == '.' && src[off + 1] == '.') {
                dest_off = prev_slash;
                prev_slash = a_url_find_prev_slash(dest, dest_off);
                for (off += 2; off < len && src[off] != '/'; off++)
                    ;
                continue;
            } else if (off < len && src[off] == '.') {
                /* "/." */
                off++;
                continue;
            }
            prev_slash = dest_off;
        }
        dest[dest_off++] = decoded;
    }

    if (dest_off == 0) {
        normalized_path.base = aura_strdup(mc, "/");
        normalized_path.len = 1;
    } else {
        normalized_path.base = aura_strndup(mc, dest, dest_off);
        normalized_path.len = dest_off;
    }

    aura_free(dest);
    return normalized_path;
}

static int a_parse_scheme(const uint8_t *src, size_t len, int *scheme) {
    int rv = -1;

    if (len < 5)
        return -1;

    if (memcmp(src, "http:", 5) == 0) {
        *scheme = 1;
        rv = 5;
    } else if (memcmp(src, "https:", 6) == 0) {
        *scheme = 2;
        rv = 6;
    } else {
        *scheme = 0;
    }

    return rv;
}

static int a_parse_authority(struct aura_memory_ctx *mc, char *src, size_t len, struct aura_url *url) {
    char *start, *end, *ptr;
    uint32_t port;

    if (len == 0)
        return -1;

    start = src;
    end = src + len;

    /* IPv6 */
    if (*start == '[') {
        ++start;
        ptr = memchr(start, ']', len);
        if (!ptr)
            return -1;

        url->authority.host.base = aura_strndup(mc, start, ptr - start);
        url->authority.host.len = ptr - start;
        start = ptr + 1;
    } else {
        /* IPv4 */
        size_t _len;
        if ((ptr = memchr(start, ':', len)) || (ptr = memchr(start, '?', len)) || (ptr = memchr(start, '/', len))) {
            _len = ptr - start;
        } else {
            ptr = end;
            _len = ptr - start;
        }

        url->authority.host.len = _len;
        url->authority.host.base = aura_strndup(mc, start, _len);
        start = ptr;
    }

    /* Empty host */
    if (url->authority.host.len == 0)
        return -1;

    /* port */
    port = 0;
    if (start != end && *start == ':') {
        for (++start; start != end; ++start) {
            if ('0' <= *start && *start <= '9') {
                port = port * 10 + *start - '0';
                if (port > 65535)
                    return -1;
            } else if (*start == '/' || *start == '?')
                break;
        }
    }
    url->authority.port = port;

    return (start - src);
}

int aura_parse_host_port(struct aura_memory_ctx *mc, char *src, size_t len, struct aura_url *url) {
    return a_parse_authority(mc, src, len, url);
}

static int a_parse_path(struct aura_memory_ctx *mc, char *src, size_t len, struct aura_url *url) {
    char *start, *end, *ptr;
    size_t _len;

    if (len == 0 || *src == '?') {
        url->path.base = aura_strndup(mc, "/", 1);
        url->path.len = 1;
        return 0;
    }

    start = src;
    end = src + len;
    if (*start == '/') {
        // ++start;
        if ((ptr = memchr(start, '?', len)) || (ptr = memchr(start, '#', len))) {
            _len = ptr - start;
            end = ptr;
        } else {
            _len = end - start;
            ptr = end;
        }

        if (_len == 0) {
            url->path.base = aura_strndup(mc, "/", 1);
            url->path.len = 1;
        } else {
            url->path.base = aura_strndup(mc, start, _len);
            url->path.len = _len;
        }
    }

    return (end - start);
}

static int a_parse_query(struct aura_memory_ctx *mc, char *src, size_t len, struct aura_url *url) {
    char *start, *end;

    if (len == 0) {
        url->query.base = NULL;
        url->query.len = 0;
        return 0;
    }

    start = src;
    end = src + len;
    if (*start == '?') {
        ++start;
        url->query.base = aura_strndup(mc, start, len);
        url->query.len = len;
    }

    return 0;
}

int aura_url_get_default_port(struct aura_url *url) {
    if (url->authority.port != 0)
        return url->authority.port;
    else if (url->scheme == 1)
        return 80;
    else if (url->scheme == 2)
        return 443;
    else
        return 0;
}

int aura_url_parse(struct aura_memory_ctx *mc, const char *url_str, size_t len, struct aura_url *url) {
    int res;
    char *start;

    if (len == 0)
        return -1;

    start = (char *)url_str;

    if ((res = a_parse_scheme(url_str, len, &url->scheme)) < 0)
        return res;

    start += res;
    len -= res;
    if (*start == '/' && *(start + 1) == '/') {
        start += 2;
        len -= 2;
    }

    if ((res = a_parse_authority(mc, start, len, url)) < 0)
        return res;

    start += res;
    len -= res;
    if ((res = a_parse_path(mc, start, len, url)) < 0)
        return res;

    start += res;
    len -= res;
    return a_parse_query(mc, start, len, url);
}
