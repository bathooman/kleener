/* CoAP diff-testing RECORDING monitor: request Type (2 bits: CON/NON/ACK/RST).
 * Injects symbolic type on the request, records the response, terminates.
 * Reply behaviour to each type (ACK expected / none / ACK-or-RST-as-request) is
 * where impls diverge most. The name "coap_req_type" MUST match across both runs. */

#include "klee/Protocols/coap/coap_monitors.h"
#include "klee/Protocols/coap/coap_packets.h"
#include "klee/Support/Protocols/helper.h"
#include "klee/klee.h"

#define INIT     0
#define INJECTED 1
#define DONE     2

void type_diff_testing_server(CoapMessage *message, bool is_message_client_generated)
{
    static int state = INIT;

    if (is_message_client_generated && state == INIT)
    {
        kleener_make_symbolic(&message->header.type,
                              sizeof(message->header.type),
                              "coap_req_type");
        state = INJECTED;
    }
    else if (!is_message_client_generated && state == INJECTED)
    {
        generate_coap_output(message);
        state = DONE;
    }
}
