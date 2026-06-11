#include "klee/Protocols/coap/coap_monitors.h"
#include "klee/Protocols/coap/coap_packets.h"
#include "klee/Support/Protocols/helper.h"
#include "klee/klee.h"
#include <assert.h>

/* Requirement (CoAP RFC 7252 §§4.1-4.3, Matching Message Type):
 *   - Confirmable (CON)    : code = request | response | empty (CoAP ping)
 *   - Non-confirmable (NON): code = request | response (NEVER empty)
 *   - Acknowledgement (ACK): code = response | empty (NEVER a request)
 *   - Reset (RST)          : code = empty (ONLY)
 *
 * Historical libcoap bug (fixed in PR #1295): the server accepted an inbound
 * ACK that carried a *request* code instead of a response code, responding to
 * it with the requested resource. This is the bug shape we reproduce.
 *
 * Inject Type=ACK while leaving the Code at GET (a request code on an ACK,
 * which §4.3 forbids); assert the SUT did not reply with a NON success response
 * (the PR #1295 bug shape).
 */

#define INIT     0
#define INJECTED 1

static int local_state = INIT;

void is_coap_matching_message_type(CoapMessage *message, bool is_message_client_generated)
{
    if (is_message_client_generated && local_state == INIT)
    {
        /* INJECT: force Type=ACK on the inbound request. Type lives in
         * bits 4-5 of the parsed struct (it's a uint8_t in the header
         * struct after parsing); the dispatcher will repack it into the
         * wire byte's Type field via serialize_coap_message. */
        message->header.type = COAP_TYPE_ACK;
        local_state = INJECTED;
    }
    else if (!is_message_client_generated && local_state == INJECTED)
    {
        /* PR #1295 bug shape: a server fails to reject an erroneous ACK that
         * carries a request and instead responds with the requested resource
         * in a non-confirmable message. Fire only on that NON-with-success-code
         * response — that is what PR #1295 fixed; if libcoap rejected it (silent
         * drop or RST) the INJECTED branch is never reached. */
        bool is_non     = (message->header.type == COAP_TYPE_NON);
        uint8_t class   = (uint8_t)(message->header.code >> 5);
        bool is_success = (class == 2);
        assert(!(is_non && is_success) &&
               "SUT replied with NON+success to ACK+request-code (PR #1295 bug shape)");
    }
}
