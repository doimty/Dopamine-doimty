#include "../BaseBin/libroothider/src/app_isolation_reply.h"
#include <assert.h>
#include <errno.h>
#include <stdint.h>
#include <stdio.h>

static xpc_object_t success_reply(void)
{
    xpc_object_t reply = xpc_dictionary_create(NULL, NULL, 0);
    xpc_dictionary_set_uint64(reply, "isolation-protocol", RH_APP_ISOLATION_PROTOCOL);
    xpc_dictionary_set_int64(reply, "result", 0);
    xpc_dictionary_set_bool(reply, "repair-applied", true);
    return reply;
}
int main(void)
{
    assert(rh_app_isolation_reply_status(NULL) == EPROTO);
    xpc_object_t reply = xpc_dictionary_create(NULL, NULL, 0);
    assert(rh_app_isolation_reply_status(reply) == EPROTO); /* old helper unknown request */
    xpc_dictionary_set_int64(reply, "result", 0);
    assert(rh_app_isolation_reply_status(reply) == EPROTO);
    xpc_release(reply);
    reply = success_reply();
    assert(rh_app_isolation_reply_status(reply) == 0);
    xpc_dictionary_set_bool(reply, "repair-applied", false);
    assert(rh_app_isolation_reply_status(reply) == EPROTO);
    xpc_dictionary_set_int64(reply, "result", EBUSY);
    assert(rh_app_isolation_reply_status(reply) == EBUSY);
    xpc_dictionary_set_int64(reply, "result", -1);
    assert(rh_app_isolation_reply_status(reply) == EIO);
    xpc_dictionary_set_int64(reply, "result", INT64_MAX);
    assert(rh_app_isolation_reply_status(reply) == EIO);
    xpc_release(reply);
    for (unsigned bad = 0; bad < 6; bad++) {
        reply = success_reply();
        switch (bad) {
            case 0: xpc_dictionary_set_uint64(reply, "result", 0); break;
            case 1: xpc_dictionary_set_bool(reply, "result", false); break;
            case 2: xpc_dictionary_set_string(reply, "result", "0"); break;
            case 3: xpc_dictionary_set_int64(reply, "isolation-protocol", 1); break;
            case 4: xpc_dictionary_set_uint64(reply, "isolation-protocol", 2); break;
            case 5: xpc_dictionary_set_int64(reply, "repair-applied", 1); break;
        }
        assert(rh_app_isolation_reply_status(reply) == EPROTO);
        xpc_release(reply);
    }
    xpc_object_t wrong = xpc_string_create("not a reply");
    assert(rh_app_isolation_reply_status(wrong) == EPROTO);
    xpc_release(wrong);
    puts("app-isolation-reply: real XPC typed protocol, old helper and malformed acknowledgment checks passed");
    return 0;
}
