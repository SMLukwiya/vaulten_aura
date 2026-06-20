#ifndef AURA_DMN_DB_BROKER
#define AURA_DMN_DB_BROKER

#include "db/db.h"
#include "db/db_broker.h"
#include "unix/sock.h"

/** Service db requests from server client */
int aura_dmn_fetch_request(struct iovec *, int, AURA_DBHANDLE db);

#endif