/* CoAP diff-testing RECORDING monitor: request Version (2 bits, 0..3).
 * Injects symbolic version on the request, records the response, terminates.
 * Probes non-1 version handling (RFC 7252 §3: silently ignore — impls split on
 * drop vs RST). The name "coap_req_version" MUST match across both runs. */

#include "klee/Protocols/coap/coap_monitors.h"
#include "klee/Protocols/coap/coap_packets.h"
#include "klee/Support/Protocols/helper.h"
#include "klee/klee.h"

#define INIT     0
#define INJECTED 1
#define DONE     2

void version_diff_testing_server(CoapMessage *message, bool is_message_client_generated)
{
    static int state = INIT;

    if (is_message_client_generated && state == INIT)
    {
        kleener_make_symbolic(&message->header.version,
                              sizeof(message->header.version),
                              "coap_req_version");
        state = INJECTED;
    }
    else if (!is_message_client_generated && state == INJECTED)
    {
        generate_coap_output(message);
        state = DONE;
    }
}
