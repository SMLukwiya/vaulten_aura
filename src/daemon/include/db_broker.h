#ifndef AURA_DMN_DB_BROKER
#define AURA_DMN_DB_BROKER

#include "db/broker.h"
#include "db/db.h"
#include "dmn.h"
#include "fn/lib.h"
#include "unix/sock.h"

/** Service db requests from server client */
int aura_dmn_db_req(struct iovec *, int, struct aura_dmn_glob_conf *gc);

#endif