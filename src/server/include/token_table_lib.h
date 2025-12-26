#include "utils_lib.h"

#ifndef str_lit
#define str_lit(s) (s), (sizeof(s) - 1)
#endif

// static struct aura_token tokens[] = {
//   {{str_lit(":authority")}, {1, 0, 1}},
//   {{str_lit(":method")}, {2, 0, 0}},
//   {{str_lit(":path")}, {4, 0, 0}},
//   {{str_lit(":protocol")}, {0, 0, 1}},
//   {{str_lit(":scheme")}, {6, 0, 0}},
//   {{str_lit(":status")}, {8, 0, 0}},
//   {{str_lit("accept")}, {19, 0, 1}},
//   {{str_lit("accept-charset")}, {15, 0, 1}},
//   {{str_lit("accept-encoding")}, {16, 0, 1}},
//   {{str_lit("accept-language")}, {17, 0, 1}},
//   {{str_lit("accept-ranges")}, {18, 0, 1}},
//   {{str_lit("access-control-allow-credentials")}, {0, 0, 0}},
//   {{str_lit("access-control-allow-headers")}, {0, 0, 1}},
//   {{str_lit("access-control-allow-methods")}, {0, 0, 1}},
//   {{str_lit("access-control-allow-origin")}, {20, 0, 1}},
//   {{str_lit("access-control-expose-headers")}, {0, 0, 1}},
//   {{str_lit("access-control-request-headers")}, {0, 0, 1}},
//   {{str_lit("access-control-request-method")}, {0, 0, 1}},
//   {{str_lit("age")}, {21, 0, 0}},
//   {{str_lit("allow")}, {22, 0, 1}},
//   {{str_lit("alt-svc")}, {0, 0, 1}},
//   {{str_lit("authorization")}, {23, 0, 0}},
//   {{str_lit("cache-control")}, {24, 0, 1}},
//   {{str_lit("cache-digest")}, {0, 0, 0}},
//   {{str_lit("connection")}, {0, 0, 0}},
//   {{str_lit("content-disposition")}, {25, 0, 1}},
//   {{str_lit("content-encoding")}, {26, 0, 1}},
//   {{str_lit("content-language")}, {27, 0, 1}},
//   {{str_lit("content-length")}, {28, 0, 0}},
//   {{str_lit("content-location")}, {29, 0, 0}},
//   {{str_lit("content-range")}, {30, 0, 0}},
//   {{str_lit("content-security-policy")}, {0, 0, 1}},
//   {{str_lit("content-type")}, {31, 0, 1}},
//   {{str_lit("cookie")}, {32, 1, 0}},
//   {{str_lit("datagram-flow-id")}, {0, 0, 0}},
//   {{str_lit("date")}, {33, 0, 1}},
//   {{str_lit("early-data")}, {0, 0, 0}},
//   {{str_lit("etag")}, {34, 0, 0}},
//   {{str_lit("expect")}, {35, 0, 1}},
//   {{str_lit("expect-ct")}, {0, 0, 1}},
//   {{str_lit("expires")}, {36, 0, 0}},
//   {{str_lit("forwarded")}, {0, 0, 1}},
//   {{str_lit("from")}, {37, 0, 1}},
//   {{str_lit("host")}, {38, 0, 0}},
//   {{str_lit("http2-settings")}, {0, 0, 0}},
//   {{str_lit("if-match")}, {39, 0, 0}},
//   {{str_lit("if-modified-since")}, {40, 0, 0}},
//   {{str_lit("if-none-match")}, {41, 0, 0}},
//   {{str_lit("if-range")}, {42, 0, 0}},
//   {{str_lit("if-unmodified-since")}, {43, 0, 0}},
//   {{str_lit("keep-alive")}, {0, 0, 0}},
//   {{str_lit("last-modified")}, {44, 0, 0}},
//   {{str_lit("link")}, {45, 0, 1}},
//   {{str_lit("location")}, {46, 0, 0}},
//   {{str_lit("max-forwards")}, {47, 0, 0}},
//   {{str_lit("no-early-hints")}, {0, 0, 1}},
//   {{str_lit("origin")}, {0, 0, 1}},
//   {{str_lit("priority")}, {0, 0, 1}},
//   {{str_lit("proxy-authenticate")}, {48, 0, 0}},
//   {{str_lit("proxy-authorization")}, {49, 0, 0}},
//   {{str_lit("proxy-connection")}, {0, 0, 0}},
//   {{str_lit("purpose")}, {0, 0, 1}},
//   {{str_lit("range")}, {50, 0, 0}},
//   {{str_lit("referer")}, {51, 0, 1}},
//   {{str_lit("refresh")}, {52, 0, 0}},
//   {{str_lit("retry-after")}, {53, 0, 1}},
//   {{str_lit("server")}, {54, 0, 1}},
//   {{str_lit("set-cookie")}, {55, 1, 0}},
//   {{str_lit("strict-transport-security")}, {56, 0, 1}},
//   {{str_lit("te")}, {0, 0, 1}},
//   {{str_lit("timing-allow-origin")}, {0, 0, 1}},
//   {{str_lit("transfer-encoding")}, {57, 0, 0}},
//   {{str_lit("upgrade")}, {0, 0, 0}},
//   {{str_lit("upgrade-insecure-requests")}, {0, 0, 1}},
//   {{str_lit("user-agent")}, {58, 0, 1}},
//   {{str_lit("vary")}, {59, 0, 1}},
//   {{str_lit("via")}, {60, 0, 0}},
//   {{str_lit("www-authenticate")}, {61, 0, 0}},
//   {{str_lit("x-compress-hint")}, {0, 0, 0}},
//   {{str_lit("x-content-type-options")}, {0, 0, 1}},
//   {{str_lit("x-forwarded-for")}, {0, 0, 1}},
//   {{str_lit("x-frame-options")}, {0, 0, 1}},
//   {{str_lit("x-reproxy-url")}, {0, 0, 0}},
//   {{str_lit("x-traffic")}, {0, 0, 0}},
//   {{str_lit("x-xss-protection")}, {0, 0, 1}},
//   /** @todo: add my custom headers here  */
// };

// static size_t num_of_token = ARRAY_SIZE(tokens);
#define STATIC_TABLE_ENTRY(name, value, token, index) \
    {                                                 \
      str_lit(name), str_lit(value), token, index}

static struct aura_hpack_static_table_entry hpack_static_table[62] = {
  STATIC_TABLE_ENTRY("", "", 0, 0),
  //   {A_TOKEN_AUTHORITY, {str_lit("")}},
  STATIC_TABLE_ENTRY(":authority", "", A_TOKEN_AUTHORITY, 1),
  // {A_TOKEN_METHOD, {str_lit("GET")}},
  STATIC_TABLE_ENTRY(":method", "GET", A_TOKEN_METHOD, 2),
  // {A_TOKEN_METHOD, {str_lit("POST")}},
  STATIC_TABLE_ENTRY(":method", "POST", A_TOKEN_METHOD, 3),
  //   {A_TOKEN_PATH, {str_lit("/")}},
  STATIC_TABLE_ENTRY(":path", "/", A_TOKEN_PATH, 4),
  //   {A_TOKEN_PATH, {str_lit("/index.html")}},
  STATIC_TABLE_ENTRY(":path", "/index.html", A_TOKEN_PATH, 5),
  //   {A_TOKEN_SCHEME, {str_lit("http")}},
  STATIC_TABLE_ENTRY(":scheme", "http", A_TOKEN_SCHEME, 6),
  //   {A_TOKEN_SCHEME, {str_lit("https")}},
  STATIC_TABLE_ENTRY(":scheme", "https", A_TOKEN_SCHEME, 7),
  //   {A_TOKEN_STATUS, {str_lit("200")}},
  STATIC_TABLE_ENTRY(":status", "200", A_TOKEN_STATUS, 8),
  //   {A_TOKEN_STATUS, {str_lit("204")}},
  STATIC_TABLE_ENTRY(":status", "204", A_TOKEN_STATUS, 9),
  //   {A_TOKEN_STATUS, {str_lit("206")}},
  STATIC_TABLE_ENTRY(":status", "206", A_TOKEN_STATUS, 10),
  //   {A_TOKEN_STATUS, {str_lit("304")}},
  STATIC_TABLE_ENTRY(":status", "304", A_TOKEN_STATUS, 11),
  //   {A_TOKEN_STATUS, {str_lit("400")}},
  STATIC_TABLE_ENTRY(":status", "400", A_TOKEN_STATUS, 12),
  //   {A_TOKEN_STATUS, {str_lit("404")}},
  STATIC_TABLE_ENTRY(":status", "404", A_TOKEN_STATUS, 13),
  //   {A_TOKEN_STATUS, {str_lit("500")}},
  STATIC_TABLE_ENTRY(":status", "500", A_TOKEN_STATUS, 14),
  //   {A_TOKEN_ACCEPT_CHARSET, {str_lit("")}},
  STATIC_TABLE_ENTRY("accept-charset", "", A_TOKEN_ACCEPT_CHARSET, 15),
  //   {A_TOKEN_ACCEPT_ENCODING, {str_lit("gzip, deflate")}},
  STATIC_TABLE_ENTRY("accept-encoding", "gzip, deflate", A_TOKEN_ACCEPT_ENCODING, 16),
  //   {A_TOKEN_ACCEPT_LANGUAGE, {str_lit("")}},
  STATIC_TABLE_ENTRY("accept-language", "", A_TOKEN_ACCEPT_LANGUAGE, 17),
  //   {A_TOKEN_ACCEPT_RANGES, {str_lit("")}},
  STATIC_TABLE_ENTRY("accept-ranges", "", A_TOKEN_ACCEPT_RANGES, 18),
  //   {A_TOKEN_ACCEPT, {str_lit("")}},
  STATIC_TABLE_ENTRY("accept", "", A_TOKEN_ACCEPT, 19),
  //   {A_TOKEN_ACCESS_CONTROL_ALLOW_ORIGIN, {str_lit("")}},
  STATIC_TABLE_ENTRY("access-control-allow-origin", "", A_TOKEN_ACCESS_CONTROL_ALLOW_ORIGIN, 20),
  //   {A_TOKEN_AGE, {str_lit("")}},
  STATIC_TABLE_ENTRY("age", "", A_TOKEN_AGE, 21),
  //   {A_TOKEN_ALLOW, {str_lit("")}},
  STATIC_TABLE_ENTRY("allow", "", A_TOKEN_ALLOW, 22),
  //   {A_TOKEN_AUTHORIZATION, {str_lit("")}},
  STATIC_TABLE_ENTRY("authorization", "", A_TOKEN_AUTHORIZATION, 23),
  //   {A_TOKEN_CACHE_CONTROL, {str_lit("")}},
  STATIC_TABLE_ENTRY("cache-control", "", A_TOKEN_CACHE_CONTROL, 24),
  //   {A_TOKEN_CONTENT_DISPOSITION, {str_lit("")}},
  STATIC_TABLE_ENTRY("content-disposition", "", A_TOKEN_CONTENT_DISPOSITION, 25),
  //   {A_TOKEN_CONTENT_ENCODING, {str_lit("")}},
  STATIC_TABLE_ENTRY("content-encoding", "", A_TOKEN_CONTENT_ENCODING, 26),
  //   {A_TOKEN_CONTENT_LANGUAGE, {str_lit("")}},
  STATIC_TABLE_ENTRY("content-language", "", A_TOKEN_CONTENT_LANGUAGE, 27),
  //   {A_TOKEN_CONTENT_LENGTH, {str_lit("")}},
  STATIC_TABLE_ENTRY("content-length", "", A_TOKEN_CONTENT_LENGTH, 28),
  //   {A_TOKEN_CONTENT_LOCATION, {str_lit("")}},
  STATIC_TABLE_ENTRY("content-location", "", A_TOKEN_CONTENT_LOCATION, 29),
  //   {A_TOKEN_CONTENT_RANGE, {str_lit("")}},
  STATIC_TABLE_ENTRY("content-range", "", A_TOKEN_CONTENT_RANGE, 30),
  //   {A_TOKEN_CONTENT_TYPE, {str_lit("")}},
  STATIC_TABLE_ENTRY("content-type", "", A_TOKEN_CONTENT_TYPE, 31),
  //   {A_TOKEN_COOKIE, {str_lit("")}},
  STATIC_TABLE_ENTRY("cookie", "", A_TOKEN_COOKIE, 32),
  //   {A_TOKEN_DATE, {str_lit("")}},
  STATIC_TABLE_ENTRY("date", "", A_TOKEN_DATE, 33),
  //   {A_TOKEN_ETAG, {str_lit("")}},
  STATIC_TABLE_ENTRY("etag", "", A_TOKEN_ETAG, 34),
  //   {A_TOKEN_EXPECT, {str_lit("")}},
  STATIC_TABLE_ENTRY("expect", "", A_TOKEN_EXPECT, 35),
  //   {A_TOKEN_EXPIRES, {str_lit("")}},
  STATIC_TABLE_ENTRY("expires", "", A_TOKEN_EXPIRES, 36),
  //   {A_TOKEN_FROM, {str_lit("")}},
  STATIC_TABLE_ENTRY("from", "", A_TOKEN_FROM, 37),
  //   {A_TOKEN_HOST, {str_lit("")}},
  STATIC_TABLE_ENTRY("host", "", A_TOKEN_HOST, 38),
  //   {A_TOKEN_IF_MATCH, {str_lit("")}},
  STATIC_TABLE_ENTRY("if-match", "", A_TOKEN_IF_MATCH, 39),
  //   {A_TOKEN_IF_MODIFIED_SINCE, {str_lit("")}},
  STATIC_TABLE_ENTRY("if-modified-since", "", A_TOKEN_IF_MODIFIED_SINCE, 40),
  //   {A_TOKEN_IF_NONE_MATCH, {str_lit("")}},
  STATIC_TABLE_ENTRY("if-none-match", "", A_TOKEN_IF_NONE_MATCH, 41),
  //   {A_TOKEN_IF_RANGE, {str_lit("")}},
  STATIC_TABLE_ENTRY("if-range", "", A_TOKEN_IF_RANGE, 42),
  //   {A_TOKEN_IF_UNMODIFIED_SINCE, {str_lit("")}},
  STATIC_TABLE_ENTRY("if-unmodified-since", "", A_TOKEN_IF_UNMODIFIED_SINCE, 43),
  //   {A_TOKEN_LAST_MODIFIED, {str_lit("")}},
  STATIC_TABLE_ENTRY("last-modified", "", A_TOKEN_LAST_MODIFIED, 44),
  //   {A_TOKEN_LINK, {str_lit("")}},
  STATIC_TABLE_ENTRY("link", "", A_TOKEN_LINK, 45),
  //   {A_TOKEN_LOCATION, {str_lit("")}},
  STATIC_TABLE_ENTRY("location", "", A_TOKEN_LOCATION, 46),
  //   {A_TOKEN_MAX_FORWARDS, {str_lit("")}},
  STATIC_TABLE_ENTRY("max-forwards", "", A_TOKEN_MAX_FORWARDS, 47),
  //   {A_TOKEN_PROXY_AUTHENTICATE, {str_lit("")}},
  STATIC_TABLE_ENTRY("proxy-authenticate", "", A_TOKEN_PROXY_AUTHENTICATE, 48),
  //   {A_TOKEN_PROXY_AUTHORIZATION, {str_lit("")}},
  STATIC_TABLE_ENTRY("proxy-authorization", "", A_TOKEN_PROXY_AUTHORIZATION, 49),
  //   {A_TOKEN_RANGE, {str_lit("")}},
  STATIC_TABLE_ENTRY("range", "", A_TOKEN_RANGE, 50),
  //   {A_TOKEN_REFERER, {str_lit("")}},
  STATIC_TABLE_ENTRY("referer", "", A_TOKEN_REFERER, 51),
  //   {A_TOKEN_REFRESH, {str_lit("")}},
  STATIC_TABLE_ENTRY("refresh", "", A_TOKEN_REFRESH, 52),
  //   {A_TOKEN_RETRY_AFTER, {str_lit("")}},
  STATIC_TABLE_ENTRY("retry-after", "", A_TOKEN_RETRY_AFTER, 53),
  //   {A_TOKEN_SERVER, {str_lit("")}},
  STATIC_TABLE_ENTRY("server", "", A_TOKEN_SERVER, 54),
  //   {A_TOKEN_SET_COOKIE, {str_lit("")}},
  STATIC_TABLE_ENTRY("set-cookie", "", A_TOKEN_SET_COOKIE, 55),
  //   {A_TOKEN_STRICT_TRANSPORT_SECURITY, {str_lit("")}},
  STATIC_TABLE_ENTRY("strict-transport-security", "", A_TOKEN_STRICT_TRANSPORT_SECURITY, 56),
  //   {A_TOKEN_TRANSFER_ENCODING, {str_lit("")}},
  STATIC_TABLE_ENTRY("transfer-encoding", "", A_TOKEN_TRANSFER_ENCODING, 57),
  //   {A_TOKEN_USER_AGENT, {str_lit("")}},
  STATIC_TABLE_ENTRY("user-agent", "", A_TOKEN_USER_AGENT, 58),
  //   {A_TOKEN_VARY, {str_lit("")}},
  STATIC_TABLE_ENTRY("vary", "", A_TOKEN_VARY, 59),
  //   {A_TOKEN_VIA, {str_lit("")}},
  STATIC_TABLE_ENTRY("via", "", A_TOKEN_VIA, 60),
  //   {A_TOKEN_WWW_AUTHENTICATE, {str_lit("")}}
  STATIC_TABLE_ENTRY("www-authenticate", "", A_TOKEN_WWW_AUTHENTICATE, 61),
  /**/
};

// static const struct aura_token *lookup_token(const char *name, size_t len) {
static int32_t lookup_token(const char *name, size_t len) {
    switch (len) {
    case 2:
        switch (name[1]) {
        case 'e':
            if (memcmp(name, "t", 1) == 0)
                return A_TOKEN_TE;
            break;
        }
        break;
    case 3:
        switch (name[2]) {
        case 'a':
            if (memcmp(name, "vi", 2) == 0)
                return A_TOKEN_VIA;
            break;
        case 'e':
            if (memcmp(name, "ag", 2) == 0)
                return A_TOKEN_AGE;
            break;
        }
        break;
    case 4:
        switch (name[3]) {
        case 'e':
            if (memcmp(name, "dat", 3) == 0)
                return A_TOKEN_DATE;
            break;
        case 'g':
            if (memcmp(name, "eta", 3) == 0)
                return A_TOKEN_ETAG;
            break;
        case 'k':
            if (memcmp(name, "lin", 3) == 0)
                return A_TOKEN_LINK;
            break;
        case 'm':
            if (memcmp(name, "fro", 3) == 0)
                return A_TOKEN_FROM;
            break;
        case 't':
            if (memcmp(name, "hos", 3) == 0)
                return A_TOKEN_HOST;
            break;
        case 'y':
            if (memcmp(name, "var", 3) == 0)
                return A_TOKEN_VARY;
            break;
        }
        break;
    case 5:
        switch (name[4]) {
        case 'e':
            if (memcmp(name, "rang", 4) == 0)
                return A_TOKEN_RANGE;
            break;
        case 'h':
            if (memcmp(name, ":pat", 4) == 0)
                return A_TOKEN_PATH;
            break;
        case 'w':
            if (memcmp(name, "allo", 4) == 0)
                return A_TOKEN_ALLOW;
            break;
        }
        break;
    case 6:
        switch (name[5]) {
        case 'e':
            if (memcmp(name, "cooki", 5) == 0)
                return A_TOKEN_COOKIE;
            break;
        case 'r':
            if (memcmp(name, "serve", 5) == 0)
                return A_TOKEN_SERVER;
            break;
        case 't':
            if (memcmp(name, "accep", 5) == 0)
                return A_TOKEN_ACCEPT;
            if (memcmp(name, "expec", 5) == 0)
                return A_TOKEN_EXPECT;
            break;
        }
        break;
    case 7:
        switch (name[6]) {
        case 'd':
            if (memcmp(name, ":metho", 6) == 0)
                return A_TOKEN_METHOD;
            break;
        case 'e':
            if (memcmp(name, ":schem", 6) == 0)
                return A_TOKEN_SCHEME;
            break;
        case 'h':
            if (memcmp(name, "refres", 6) == 0)
                return A_TOKEN_REFRESH;
            break;
        case 'r':
            if (memcmp(name, "refere", 6) == 0)
                return A_TOKEN_REFERER;
            break;
        case 's':
            if (memcmp(name, ":statu", 6) == 0)
                return A_TOKEN_STATUS;
            if (memcmp(name, "expire", 6) == 0)
                return A_TOKEN_EXPIRES;
            break;
        }
        break;
    case 8:
        switch (name[7]) {
        case 'e':
            if (memcmp(name, "if-rang", 7) == 0)
                return A_TOKEN_IF_RANGE;
            break;
        case 'h':
            if (memcmp(name, "if-matc", 7) == 0)
                return A_TOKEN_IF_MATCH;
            break;
        case 'n':
            if (memcmp(name, "locatio", 7) == 0)
                return A_TOKEN_LOCATION;
            break;
        }
        break;
    case 9:
        switch (name[8]) {
        case 'l':
            if (memcmp(name, ":protoco", 8) == 0)
                return A_TOKEN_PROTOCOL;
            break;
        }
        break;
    case 10:
        switch (name[9]) {
        case 'a':
            if (memcmp(name, "early-dat", 9) == 0)
                return A_TOKEN_EARLY_DATA;
            break;
        case 'e':
            if (memcmp(name, "keep-aliv", 9) == 0)
                return A_TOKEN_KEEP_ALIVE;
            if (memcmp(name, "set-cooki", 9) == 0)
                return A_TOKEN_SET_COOKIE;
            break;
        case 'n':
            if (memcmp(name, "connectio", 9) == 0)
                return A_TOKEN_CONNECTION;
            break;
        case 't':
            if (memcmp(name, "user-agen", 9) == 0)
                return A_TOKEN_USER_AGENT;
            break;
        case 'y':
            if (memcmp(name, ":authorit", 9) == 0)
                return A_TOKEN_AUTHORITY;
            break;
        }
        break;
    case 11:
        switch (name[10]) {
        case 'r':
            if (memcmp(name, "retry-afte", 10) == 0)
                return A_TOKEN_RETRY_AFTER;
            break;
        }
        break;
    case 12:
        switch (name[11]) {
        case 'e':
            if (memcmp(name, "content-typ", 11) == 0)
                return A_TOKEN_CONTENT_TYPE;
            break;
        case 's':
            if (memcmp(name, "max-forward", 11) == 0)
                return A_TOKEN_MAX_FORWARDS;
            break;
        }
        break;
    case 13:
        switch (name[12]) {
        case 'd':
            if (memcmp(name, "last-modifie", 12) == 0)
                return A_TOKEN_LAST_MODIFIED;
            break;
        case 'e':
            if (memcmp(name, "content-rang", 12) == 0)
                return A_TOKEN_CONTENT_RANGE;
            break;
        case 'h':
            if (memcmp(name, "if-none-matc", 12) == 0)
                return A_TOKEN_IF_NONE_MATCH;
            break;
        case 'l':
            if (memcmp(name, "cache-contro", 12) == 0)
                return A_TOKEN_CACHE_CONTROL;
            break;
        case 'n':
            if (memcmp(name, "authorizatio", 12) == 0)
                return A_TOKEN_AUTHORIZATION;
            break;
        case 's':
            if (memcmp(name, "accept-range", 12) == 0)
                return A_TOKEN_ACCEPT_RANGES;
            break;
        }
        break;
    case 14:
        switch (name[13]) {
        case 'h':
            if (memcmp(name, "content-lengt", 13) == 0)
                return A_TOKEN_CONTENT_LENGTH;
            break;
        case 't':
            if (memcmp(name, "accept-charse", 13) == 0)
                return A_TOKEN_ACCEPT_CHARSET;
            break;
        }
        break;
    case 15:
        switch (name[14]) {
        case 'e':
            if (memcmp(name, "accept-languag", 14) == 0)
                return A_TOKEN_ACCEPT_LANGUAGE;
            break;
        case 'g':
            if (memcmp(name, "accept-encodin", 14) == 0)
                return A_TOKEN_ACCEPT_ENCODING;
            break;
        }
        break;
    case 16:
        switch (name[15]) {
        case 'e':
            if (memcmp(name, "content-languag", 15) == 0)
                return A_TOKEN_CONTENT_LANGUAGE;
            if (memcmp(name, "www-authenticat", 15) == 0)
                return A_TOKEN_WWW_AUTHENTICATE;
            break;
        case 'g':
            if (memcmp(name, "content-encodin", 15) == 0)
                return A_TOKEN_CONTENT_ENCODING;
            break;
        case 'n':
            if (memcmp(name, "content-locatio", 15) == 0)
                return A_TOKEN_CONTENT_LOCATION;
        }
        break;
    case 17:
        switch (name[16]) {
        case 'e':
            if (memcmp(name, "if-modified-sinc", 16) == 0)
                return A_TOKEN_IF_MODIFIED_SINCE;
            break;
        case 'g':
            if (memcmp(name, "transfer-encodin", 16) == 0)
                return A_TOKEN_TRANSFER_ENCODING;
            break;
        }
        break;
    case 18:
        switch (name[17]) {
        case 'e':
            if (memcmp(name, "proxy-authenticat", 17) == 0)
                return A_TOKEN_PROXY_AUTHENTICATE;
            break;
        }
        break;
    case 19:
        switch (name[18]) {
        case 'e':
            if (memcmp(name, "if-unmodified-sinc", 18) == 0)
                return A_TOKEN_IF_UNMODIFIED_SINCE;
            break;
        case 'n':
            if (memcmp(name, "content-dispositio", 18) == 0)
                return A_TOKEN_CONTENT_DISPOSITION;
            if (memcmp(name, "proxy-authorizatio", 18) == 0)
                return A_TOKEN_PROXY_AUTHORIZATION;
            break;
        }
        break;
    case 25:
        switch (name[24]) {
        case 'y':
            if (memcmp(name, "strict-transport-securit", 24) == 0)
                return A_TOKEN_STRICT_TRANSPORT_SECURITY;
            break;
        }
        break;
    case 27:
        switch (name[26]) {
        case 'n':
            if (memcmp(name, "access-control-allow-origi", 26) == 0)
                return A_TOKEN_ACCESS_CONTROL_ALLOW_ORIGIN;
            break;
        }
        break;
    }
    /** @todo: add my custom headers */

    return -1;
}
