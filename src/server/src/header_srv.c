#include "header_srv.h"
#include "server_srv.h"
#include "token_srv.h"

bool aura_add_header(struct aura_memory_ctx *mc, struct aura_http_hdrs *hdrs, const struct aura_hdr_nv *nv) {
    struct aura_hdr_nv *slot;

    if (hdrs->cnt >= hdrs->cap) {
        hdrs->cap = hdrs->cap == 0 ? 16 : hdrs->cap * 2;
        hdrs->entries = aura_realloc(mc, hdrs->entries, hdrs->cap);
        if (hdrs->entries == NULL)
            return false;
    }

    slot = &hdrs->entries[hdrs->cnt++];
    memcpy(slot, nv, sizeof(*nv));
    return true;
}
