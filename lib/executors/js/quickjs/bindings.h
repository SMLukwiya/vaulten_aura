#ifndef AURA_QJS_BINDINGS_H
#define AURA_QJS_BINDINGS_H

#include <ctype.h>

#include "fn/lib.h"
#include "mem.h"
#include "quickjs.h"
#include "request/req.h"

#define A_READ 1
#define A_WRITE 2
#define A_OPEN 4
#define A_CLOSE 8

typedef void (*console_init)(JSContext *);
typedef JSValue (*aura_js_fetch_fn)(JSContext *ctx, JSValue this_val, int argc, JSValue *argv);

/* Runtime opaque data */
struct aura_qjs_rt_data {
    struct aura_mem_ctx *mc;
    struct aura_qjs_fetch_ctx *fetch_ctx;
};

typedef enum {
    A_QJS_BODY_TYPE_EMPTY,
    A_QJS_BODY_TYPE_INVALID,
    A_QJS_BODY_TYPE_ARRAY_BUFFER,
    A_QJS_BODY_TYPE_TYPED_ARRAY,
    A_QJS_BODY_TYPE_DATA_VIEW,
    A_QJS_BODY_TYPE_READABLE_STREAM,
    A_QJS_BODY_TYPE_STRING,
} a_qjs_body_t;

typedef enum {
    A_QJS_TEXT_ENCODING_UTF8 = 0,
    A_QJS_TEXT_ENCODING_UTF16LE = 1,
    A_QJS_TEXT_ENCODING_UTF16BE = 2,
} A_QJS_TextEncodingType;

/* UTF-8 Text decoder state structure */
typedef struct {
    uint32_t code_point;    /* codepoint accumulation */
    uint8_t bytes_seen;     /* Bytes processed so far */
    uint8_t bytes_needed;   /* Total bytes expected to complete processing */
    uint8_t lower_boundary; /* Spec dictated lower bound */
    uint8_t upper_boundary; /* Spec dicated upper bound */
} A_QJS_TEXT_UTF8DecoderState;

/* UTF-16 Text decoder state structure */
typedef struct {
    int lead_byte;      /* -1 if no pending byte, otherwise 0..255 */
    int lead_surrogate; /* -1 if no pending surrogate, otherwise 0xD800..0xDBFF */
    int be;             /* 1 for big-endian, 0 for little-endian */
} A_QJS_TEXT_UTF16DecoderState;

struct aura_qjs_text_decoder_data {
    A_QJS_TextEncodingType encoding; /* default or user provided encoding */
    bool fatal;                      /* Throw type error when decoding invalid data */
    bool ignore_bom;                 /* Include byte order mark in the output */
    bool bom_seen;                   /* Has encountered byte order mark */
    bool do_not_flush;

    /* Decoder state (depends on encoding) */
    union {
        A_QJS_TEXT_UTF8DecoderState utf8;
        A_QJS_TEXT_UTF16DecoderState utf16;
    } state;
};

/* Body consumer attached data */
struct aura_qjs_bc_consumer_data {
    A_QJS_TEXT_UTF8DecoderState st; /* Consumer decoder state */
    JSContext *ctx;                 /* JS Context */
    JSValue promise_resolve;        /* Resolve function */
    JSValue promise_reject;         /* Reject function */
    uint8_t *accumulator;           /* Decoded data accumulator */
    uint64_t accumulator_len;       /* Accumulator len */
    int active_consumer;            /* .text, .json, .arrayBuffer, etc */
};

struct aura_qjs_body_src;

/* Request body source ops */
struct aura_qjs_body_src_ops {
    int (*read)(struct aura_qjs_body_src *, void **dest, uint64_t *nread);
    void (*destroy)(struct aura_qjs_body_src *);
};

/* Request body source structure */
struct aura_qjs_body_src {
    struct aura_qjs_body_src_ops *ops; /* Body source ops */
    JSContext *ctx;
    union {
        struct {
            JSValue val; /* main underlying source */
            uint64_t off;
            /* Applies to only readable stream */
            JSValue js_read; /* getReader().read for readables stream */
            struct {
                uint8_t *data;
                uint64_t len;
                uint64_t off;
            } chunk;
        } js_body;
        struct {
            uint8_t *data;
            uint64_t len;
            uint64_t off;
        } bytes; /* Underlying actual data source */
    };
    a_qjs_body_t type; /* body source type */
};

/* Fetch ctx structure */
struct aura_qjs_fetch_ctx {
    int type;
    JSContext *ctx;
    JSValue resolve;
    JSValue reject;
    struct aura_qjs_body_src data_src;
    Request *req;
};

#define a_qjs_is_hi_surr(c) ((c) >= 0xD800 && (c) <= 0xDBFF)
#define a_qjs_is_lo_surr(c) ((c) >= 0xDC00 && (c) <= 0xDFFF)
#define a_qjs_surr_to_cp(hi, lo) \
    (0x10000 + (((uint32_t)(hi) - 0xD800) << 10) + ((uint32_t)(lo) - 0xDC00))

/* Handler result codes */
#define A_QJS_TEXT_HANDLER_FINISHED (-1)
#define A_QJS_TEXT_HANDLER_CONTINUE (-2)
#define A_QJS_TEXT_HANDLER_ERROR (-3)

/* Per the WHATWG Encoding spec, label matching is ASCII case-insensitive
   with leading/trailing ASCII whitespace stripped. */

static inline int aura_qjs_is_ascii_ws(char c) {
    return c == ' ' || c == '\t' || c == '\n' || c == '\f' || c == '\r';
}

static inline char aura_qjs_ascii_lower(char c) {
    if (c >= 'A' && c <= 'Z')
        return c + ('a' - 'A');
    return c;
}

/* Get encoding string representation */
static inline const char *aura_text_encoding_name(A_QJS_TextEncodingType enc) {
    switch (enc) {
    case A_QJS_TEXT_ENCODING_UTF8:
        return "utf-8";
    case A_QJS_TEXT_ENCODING_UTF16LE:
        return "utf-16le";
    case A_QJS_TEXT_ENCODING_UTF16BE:
        return "utf-16be";
    }
    return "utf-8";
}

/**
 * Encode a single code point to UTF-8,
 * return number of bytes written.
 */
static inline int aura_qjs_utf8_encode_cp(uint8_t *buf, uint32_t cp) {
    if (cp < 0x80) {
        buf[0] = (uint8_t)cp;
        return 1;
    } else if (cp < 0x800) {
        buf[0] = (uint8_t)(0xC0 | (cp >> 6));
        buf[1] = (uint8_t)(0x80 | (cp & 0x3F));
        return 2;
    } else if (cp < 0x10000) {
        buf[0] = (uint8_t)(0xE0 | (cp >> 12));
        buf[1] = (uint8_t)(0x80 | ((cp >> 6) & 0x3F));
        buf[2] = (uint8_t)(0x80 | (cp & 0x3F));
        return 3;
    } else {
        buf[0] = (uint8_t)(0xF0 | (cp >> 18));
        buf[1] = (uint8_t)(0x80 | ((cp >> 12) & 0x3F));
        buf[2] = (uint8_t)(0x80 | ((cp >> 6) & 0x3F));
        buf[3] = (uint8_t)(0x80 | (cp & 0x3F));
        return 4;
    }
}

/* Return the number of UTF-8 bytes needed for a code point. */
static inline int aura_qjs_utf8_cp_len(uint32_t cp) {
    if (cp < 0x80)
        return 1;
    if (cp < 0x800)
        return 2;
    if (cp < 0x10000)
        return 3;
    return 4;
}

/* Reset text decoder structure */
static inline void a_qjs_text_utf8_dec_reset(A_QJS_TEXT_UTF8DecoderState *st) {
    st->code_point = 0;
    st->bytes_seen = 0;
    st->bytes_needed = 0;
    st->lower_boundary = 0x80;
    st->upper_boundary = 0xBF;
}

/* Reset text encoder structure */
static inline void a_qjs_text_utf16_dec_reset(A_QJS_TEXT_UTF16DecoderState *st, int big_endian) {
    st->lead_byte = -1;
    st->lead_surrogate = -1;
    st->be = big_endian;
}

/* Initialize console logging */
void aura_js_console_init(JSContext *ctx);

/* Initialize response binding */
int aura_qjs_response_binding_init(JSContext *ctx);
/* Destroy response binding */
void aura_qjs_response_binding_destroy(JSContext *ctx);

/**/
JSValue aura_js_std_await(JSContext *ctx, JSValue obj);

/**/
void aura_js_std_dump_error(JSContext *ctx, char *msg);

/**/
JSValue aura_js_fetch(JSContext *ctx, JSValueConst this_val, int argc, JSValueConst *argv);

bool A_JS_ISResponse(JSContext *ctx, JSValue val);

/* ========================= TEST ========================= */
void aura_js_console_test_init(JSContext *ctx);
JSValue aura_js_fetch_test_fn(JSContext *ctx, JSValueConst this_val, int argc, JSValueConst *argv);

/* Initialize TextDecoder and bindings */
int aura_qjs_text_dec_init(JSContext *ctx);
/* Destroy TextDecoder and bindings */
void aura_qjs_text_dec_destroy(JSContext *ctx);

/* Initialize TextEncoder and bindings */
int aura_qjs_text_enc_init(JSContext *ctx);
/* Destroy TextEncoder and bindings */
void aura_qjs_text_enc_destroy(JSContext *ctx);

int aura_qjs_test_consumer_decode_utf8(JSContext *ctx, A_QJS_TEXT_UTF8DecoderState *st,
                                       const uint8_t *data, uint64_t len, uint8_t **data_out,
                                       uint64_t *data_out_len, bool streaming);

#endif