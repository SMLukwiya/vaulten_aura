#ifndef AURA_TOKEN_H
#define AURA_TOKEN_H

#include <stdbool.h>
#include <stdint.h>
#include <sys/uio.h>

#include "types_lib.h"

#define MAX_TOKENS 100

typedef enum {
    AURA_TOKEN_NO_COMPRESS = 0,
    AURA_TOKEN_NO_INDEX
} aura_token_flags;

struct aura_hpack_static_table_entry {
    struct aura_iovec name;
    struct aura_iovec value;
    int32_t token;
    uint32_t index;
};

typedef enum {
    A_TOKEN_AUTHORITY = 0,
    A_TOKEN_METHOD = 1,
    A_TOKEN_PATH = 3,
    A_TOKEN_SCHEME = 5,
    A_TOKEN_STATUS = 7,
    A_TOKEN_ACCEPT_CHARSET = 14,
    A_TOKEN_ACCEPT_ENCODING = 15,
    A_TOKEN_ACCEPT_LANGUAGE = 16,
    A_TOKEN_ACCEPT_RANGES = 17,
    A_TOKEN_ACCEPT = 18,
    A_TOKEN_ACCESS_CONTROL_ALLOW_ORIGIN = 19,
    A_TOKEN_AGE = 20,
    A_TOKEN_ALLOW = 21,
    A_TOKEN_AUTHORIZATION = 22,
    A_TOKEN_CACHE_CONTROL = 23,
    A_TOKEN_CONTENT_DISPOSITION = 24,
    A_TOKEN_CONTENT_ENCODING = 25,
    A_TOKEN_CONTENT_LANGUAGE = 26,
    A_TOKEN_CONTENT_LENGTH = 27,
    A_TOKEN_CONTENT_LOCATION = 28,
    A_TOKEN_CONTENT_RANGE = 29,
    A_TOKEN_CONTENT_TYPE = 30,
    A_TOKEN_COOKIE = 31,
    A_TOKEN_DATE = 32,
    A_TOKEN_ETAG = 33,
    A_TOKEN_EXPECT = 34,
    A_TOKEN_EXPIRES = 35,
    A_TOKEN_FROM = 36,
    A_TOKEN_HOST = 37,
    A_TOKEN_IF_MATCH = 38,
    A_TOKEN_IF_MODIFIED_SINCE = 39,
    A_TOKEN_IF_NONE_MATCH = 40,
    A_TOKEN_IF_RANGE = 41,
    A_TOKEN_IF_UNMODIFIED_SINCE = 42,
    A_TOKEN_LAST_MODIFIED = 43,
    A_TOKEN_LINK = 44,
    A_TOKEN_LOCATION = 45,
    A_TOKEN_MAX_FORWARDS = 46,
    A_TOKEN_PROXY_AUTHENTICATE = 47,
    A_TOKEN_PROXY_AUTHORIZATION = 48,
    A_TOKEN_RANGE = 49,
    A_TOKEN_REFERER = 50,
    A_TOKEN_REFRESH = 51,
    A_TOKEN_RETRY_AFTER = 52,
    A_TOKEN_SERVER = 53,
    A_TOKEN_SET_COOKIE = 54,
    A_TOKEN_STRICT_TRANSPORT_SECURITY = 55,
    A_TOKEN_TRANSFER_ENCODING = 56,
    A_TOKEN_USER_AGENT = 57,
    A_TOKEN_VARY = 58,
    A_TOKEN_VIA = 59,
    A_TOKEN_WWW_AUTHENTICATE = 60,
    A_TOKEN_TE,
    A_TOKEN_PROTOCOL,
    A_TOKEN_EARLY_DATA,
    A_TOKEN_KEEP_ALIVE,
    A_TOKEN_CONNECTION
} aura_token;

#include "token_table_lib.h"

static inline bool iovec_is_token(const struct aura_iovec *b) {
    int token;

    token = lookup_token(b->base, b->len);
    return token >= 0 && token <= A_TOKEN_WWW_AUTHENTICATE;
}

#endif