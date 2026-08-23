#ifndef AURA_QUICKJS_INTERNALS_H
#define AURA_QUICKJS_INTERNALS_H

#include <stdbool.h>

#include "quickjs.h"

/**
 * THIS IS MEANT TO ACT AS A BRIDGE TO THE QUICKJS INTERNALS
 *
 * Quickjs does not expose some internal structures and macros
 * that are much needed inorder to implement some
 * JS features. We create a minimalist version of
 * the same structure consisting of only the fields we need.
 */

typedef struct A_JSString A_JSString;
typedef struct A_JSObject A_JSObject;

#define A_JS_CLASS_UINT8C_ARRAY 21

/* Minimalist internal quickjs string structure */
struct A_JSString {
    uint32_t len : 31;
    uint8_t is_wide_char : 1; /* 0 = 8 bits, 1 = 16 bits characters */
    union {
        uint8_t str8[0]; /* 8 bit strings will get an extra null terminator */
        uint16_t str16[0];
    } u;
};

/* Minimalist internal quickjs object structure */
struct A_JSObject {
    union {
        struct {
            uint16_t class_id; /* see JS_CLASS_x */
        };
    };
};

#define A_INTERNAL_JS_VALUE_GET_OBJ(v) ((A_JSObject *)JS_VALUE_GET_PTR(v))
#define A_INTERNAL_JS_VALUE_GET_STRING(v) ((A_JSString *)JS_VALUE_GET_PTR(v))

/* Determines if string is wide char (utf-16) or not */
static inline bool aura_qjs_string_is_wide(JSContext *ctx, JSValueConst value, JSValue *val) {
    A_JSString *str;

    if (JS_VALUE_GET_TAG(value) != JS_TAG_STRING) {
        *val = JS_ToString(ctx, value);
        if (JS_IsException(*val)) {
            *val = JS_EXCEPTION;
            return false;
        }
    } else {
        *val = JS_DupValue(ctx, value);
    }

    str = A_INTERNAL_JS_VALUE_GET_STRING(*val);
    return str->is_wide_char;
}

/* Returns the utf-8 string */
static inline uint8_t *aura_qjs_get_str8(JSValue value, uint64_t *len) {
    A_JSString *str = A_INTERNAL_JS_VALUE_GET_STRING(value);
    *len = str->len;
    return str->u.str8;
}

/* Returns the utf-16 string */
static inline uint16_t *aura_qjs_get_str16(JSValue value, uint64_t *len) {
    A_JSString *str = A_INTERNAL_JS_VALUE_GET_STRING(value);
    *len = str->len;
    return str->u.str16;
}

/**
 * Determines the typed array instance of an object
 */
static inline bool aura_qjs_is_typed_array(JSValue val, JSTypedArrayEnum type) {
    JSValue global;
    A_JSObject *p;

    if (JS_VALUE_GET_TAG(val) != JS_TAG_OBJECT)
        return false;

    p = A_INTERNAL_JS_VALUE_GET_OBJ(val);
    return p->class_id == A_JS_CLASS_UINT8C_ARRAY + type;
}

#endif