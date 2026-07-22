#include "klee/Protocols/coap/coap_monitors.h"
#include "klee/Protocols/coap/coap_packets.h"
#include "klee/Support/Protocols/helper.h"
#include "klee/klee.h"
#include <assert.h>

/* Requirement (CoAP RFC 7252 Section 3):
 *   Version (Ver): 2-bit unsigned integer ... Implementations of this
 *   specification MUST set this field to 1 (01 binary). Other values are
 *   reserved for future versions. *Messages with unknown version numbers
 *   MUST be silently ignored.*
 *
 * Inject a Version != 1 on the request; assert the SUT produced NO response at
 * all. "Silently ignored" means the conformant server emits nothing, so any
 * outbound packet — of any type — is a violation. A conformant SUT drops the
 * message, so the assertion branch is never reached. (PR #1376 was one instance
 * of this: a server that answered with an RST instead of ignoring.)
 */

#define INIT     0
#define INJECTED 1

static int local_state = INIT;

void is_coap_version_valid(CoapMessage *message, bool is_message_client_generated)
{
    if (is_message_client_generated && local_state == INIT)
    {
        /* INJECT: make the version field symbolic, constrain it to differ
         * from the concrete-valid value of 1, and let the dispatcher write
         * the mutation back to the wire buffer. */
        uint8_t concrete_version = message->header.version;
        kleener_make_symbolic(&message->header.version,
                              sizeof(message->header.version),
                              "monitor_version");
        klee_assume(message->header.version != concrete_version);
        klee_assume(message->header.version <= 3); /* 2-bit field */

        local_state = INJECTED;
    }
    else if (!is_message_client_generated && local_state == INJECTED)
    {
        /* RFC 7252 §3 mandates that an unknown version be silently ignored — the
         * server must emit no response whatsoever. Reaching this branch means
         * the server answered the invalid-version request at all, which is a
         * violation regardless of the response type (RST, ACK, a 4.xx, or an
         * actual reply). A conformant server drops the message and never gets
         * here. */
        assert(0 &&
               "SUT responded to an invalid-version message; RFC 7252 §3 requires silent ignore");
    }
}
