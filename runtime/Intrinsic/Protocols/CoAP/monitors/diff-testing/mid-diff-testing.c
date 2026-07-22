/* Diff-testing monitor: makes ONLY the request Message ID symbolic and records
 * the response. The type is left concrete so the Message-ID input is isolated:
 * any divergence is attributable to the Message ID alone. */

#include "klee/Protocols/coap/coap_monitors.h"
#include "klee/Protocols/coap/coap_packets.h"
#include "klee/Support/Protocols/helper.h"
#include "klee/klee.h"

#define INIT     0
#define INJECTED 1
#define DONE     2

static int local_state = INIT;

void mid_diff_testing_server(CoapMessage *message, bool is_message_client_generated)
{
    if (is_message_client_generated && local_state == INIT)
    {
        kleener_make_symbolic(&message->header.message_id,
                              sizeof(message->header.message_id),
                              "coap_req_mid");
        local_state = INJECTED;
    }
    else if (!is_message_client_generated && local_state == INJECTED)
    {
        generate_coap_output_mid(message);
        local_state = DONE;
    }
}
