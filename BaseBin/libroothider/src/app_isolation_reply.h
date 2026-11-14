#ifndef APP_ISOLATION_REPLY_H
#define APP_ISOLATION_REPLY_H

#include <xpc/xpc.h>

/* Protocol1 acknowledges prelaunch hook installation, not later cache remapping. */
#define RH_APP_ISOLATION_PROTOCOL 1ULL

/* 0 only for a typed success result, matching protocol and explicit applied=true. */
int rh_app_isolation_reply_status(xpc_object_t reply);

#endif
