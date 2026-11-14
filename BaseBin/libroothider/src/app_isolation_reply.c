#include "app_isolation_reply.h"
#include <errno.h>
#include <limits.h>
#include <stdint.h>

int rh_app_isolation_reply_status(xpc_object_t reply)
{
    if (!reply || xpc_get_type(reply) != XPC_TYPE_DICTIONARY) return EPROTO;
    xpc_object_t protocol = xpc_dictionary_get_value(reply, "isolation-protocol");
    xpc_object_t result = xpc_dictionary_get_value(reply, "result");
    xpc_object_t applied = xpc_dictionary_get_value(reply, "repair-applied");
    if (!protocol || xpc_get_type(protocol) != XPC_TYPE_UINT64 ||
        xpc_uint64_get_value(protocol) != RH_APP_ISOLATION_PROTOCOL ||
        !result || xpc_get_type(result) != XPC_TYPE_INT64 ||
        !applied || xpc_get_type(applied) != XPC_TYPE_BOOL) return EPROTO;
    int64_t status = xpc_int64_get_value(result);
    if (status < 0 || status > INT_MAX) return EIO;
    if (status != 0) return (int)status;
    return xpc_bool_get_value(applied) ? 0 : EPROTO;
}
