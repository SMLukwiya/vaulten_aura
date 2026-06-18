
#ifndef str_lit
#define str_lit(s) (s), (sizeof(s) - 1)
#endif

static const char *content_type_common_values[] = {
  "application/json",
  "text/plain",
  "text/html",
  "application/x-www-form-urlencoded",
  "multipart/form-data",
  "application/octet-stream",
  "image/png",
  "image/jpeg",
  "image/webp",
  "text/css",
  "application/javascript",
};

static const char *content_encoding_common_values[] = {
  "gzip",
  "br",
  "deflate",
  "identity",
};

static const char *accept_encoding_common_values[] = {
  "gzip, deflate, br",
  "gzip",
  "br",
};

static const char *accept_common_values[] = {
  "*/*",
  "application/json",
  "text/html",
};

static const char *accept_language_common_values[] = {
  "en-US",
  "en",
  "en-US,en;q=0.9"};

static const char *cache_control_common_values[] = {
  "no-cache",
  "no-store",
  "max-age=0",
  "public. max-age=31536000",
  "private",
  "must-revalidate",
};

static const char *authorization_prefix_values[] = {
  "Bearer",
  "Basic",
};

struct aura_value_tokens {
    uint32_t token;
    struct {
        const uint8_t *str;
        size_t len;
    } *value_list;
};

struct rfc_static_tab_entry {
    struct aura_iovec name;
    struct aura_iovec value;
};

#define A_STATIC_TABLE_ENTRY(name, value) \
    {                                     \
      str_lit(name), str_lit(value)}

static struct rfc_static_tab_entry rfc_static_table[] = {
  {str_lit(""), str_lit("")},
  {str_lit(":authority"), str_lit("")},
  {str_lit(":method"), str_lit("GET")},
  {str_lit(":method"), str_lit("POST")},
  {str_lit(":path"), str_lit("/")},
  {str_lit(":path"), str_lit("/index.html")},
  {str_lit(":scheme"), str_lit("http")},
  {str_lit(":scheme"), str_lit("https")},
  {str_lit(":status"), str_lit("200")},
  {str_lit(":status"), str_lit("204")},
  {str_lit(":status"), str_lit("206")},
  {str_lit(":status"), str_lit("304")},
  {str_lit(":status"), str_lit("400")},
  {str_lit(":status"), str_lit("404")},
  {str_lit(":status"), str_lit("500")},
  {str_lit("accept-charset"), str_lit("")},
  {str_lit("accept-encoding"), str_lit("gzip, deflate")},
  {str_lit("accept-language"), str_lit("")},
  {str_lit("accept-ranges"), str_lit("")},
  {str_lit("accept"), str_lit("")},
  {str_lit("access-control-allow-origin"), str_lit("")},
  {str_lit("age"), str_lit("")},
  {str_lit("allow"), str_lit("")},
  {str_lit("authorization"), str_lit("")},
  {str_lit("cache-control"), str_lit("")},
  {str_lit("content-disposition"), str_lit("")},
  {str_lit("content-encoding"), str_lit("")},
  {str_lit("content-language"), str_lit("")},
  {str_lit("content-length"), str_lit("")},
  {str_lit("content-location"), str_lit("")},
  {str_lit("content-range"), str_lit("")},
  {str_lit("content-type"), str_lit("")},
  {str_lit("cookie"), str_lit("")},
  {str_lit("date"), str_lit("")},
  {str_lit("etag"), str_lit("")},
  {str_lit("expect"), str_lit("")},
  {str_lit("expires"), str_lit("")},
  {str_lit("from"), str_lit("")},
  {str_lit("host"), str_lit("")},
  {str_lit("if-match"), str_lit("")},
  {str_lit("if-modified-since"), str_lit("")},
  {str_lit("if-none-match"), str_lit("")},
  {str_lit("if-range"), str_lit("")},
  {str_lit("if-unmodified-since"), str_lit("")},
  {str_lit("last-modified"), str_lit("")},
  {str_lit("link"), str_lit("")},
  {str_lit("location"), str_lit("")},
  {str_lit("max-forwards"), str_lit("")},
  {str_lit("proxy-authenticate"), str_lit("")},
  {str_lit("proxy-authorization"), str_lit("")},
  {str_lit("range"), str_lit("")},
  {str_lit("referer"), str_lit("")},
  {str_lit("refresh"), str_lit("")},
  {str_lit("retry-after"), str_lit("")},
  {str_lit("server"), str_lit("")},
  {str_lit("set-cookie"), str_lit("")},
  {str_lit("strict-transport-security"), str_lit("")},
  {str_lit("transfer-encoding"), str_lit("")},
  {str_lit("user-agent"), str_lit("")},
  {str_lit("vary"), str_lit("")},
  {str_lit("via"), str_lit("")},
  {str_lit("www-authenticate"), str_lit("")},
};

static uint16_t lookup_token(const char *name, size_t len) {
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
        case 'y':
            if (memcmp(name, "priorit", 7) == 0)
                return A_TOKEN_PRIORITY;
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
    default:
        return A_TOKEN_NONE;
    }

    return 0;
}

struct aura_token {
    struct aura_interned_str *name;
    uint32_t flags;
};
