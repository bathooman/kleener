/* Diff-testing monitor: makes request Code symbolic, records the response. */

#include "klee/Protocols/coap/coap_monitors.h"
#include "klee/Protocols/coap/coap_packets.h"
#include "klee/Support/Protocols/helper.h"
#include "klee/klee.h"

#define INIT     0
#define INJECTED 1
#define DONE     2

static int local_state = INIT;

void code_diff_testing_server(CoapMessage *message, bool is_message_client_generated)
{
    if (is_message_client_generated && local_state == INIT)
    {
        kleener_make_symbolic(&message->header.code,
                              sizeof(message->header.code),
                              "coap_req_code");
        local_state = INJECTED;
    }
    else if (!is_message_client_generated && local_state == INJECTED)
    {
        generate_coap_output(message);
        local_state = DONE;
    }
}
