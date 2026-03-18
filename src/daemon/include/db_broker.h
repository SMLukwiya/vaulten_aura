#ifndef AURA_DMN_DB_BROKER
#define AURA_DMN_DB_BROKER

#include "db/db.h"
#include "db/db_broker.h"
#include "unix_socket_lib.h"

/** Service db requests from server client */
int aura_dmn_fetch_request(AURA_DBHANDLE db, struct iovec *, int);

#endif