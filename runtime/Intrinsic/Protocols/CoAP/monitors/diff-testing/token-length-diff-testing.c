/* CoAP diff-testing RECORDING monitor: request Token Length (4 bits, 0..15).
 * Injects symbolic TKL on the request, records the response, terminates. The
 * serializer writes the symbolic TKL nibble but keeps the concrete token body,
 * so DECLARED length varies while actual bytes stay fixed — probes reserved TKL
 * 9..15 and declared-vs-actual mismatch (RFC 7252 §3: format error; impls split
 * on drop/4.00/RST). The name "coap_req_token_length" MUST match across both runs. */

#include "klee/Protocols/coap/coap_monitors.h"
#include "klee/Protocols/coap/coap_packets.h"
#include "klee/Support/Protocols/helper.h"
#include "klee/klee.h"

#define INIT     0
#define INJECTED 1
#define DONE     2

void token_length_diff_testing_server(CoapMessage *message, bool is_message_client_generated)
{
    static int state = INIT;

    if (is_message_client_generated && state == INIT)
    {
        kleener_make_symbolic(&message->header.token_length,
                              sizeof(message->header.token_length),
                              "coap_req_token_length");
        state = INJECTED;
    }
    else if (!is_message_client_generated && state == INJECTED)
    {
        generate_coap_output(message);
        state = DONE;
    }
}
