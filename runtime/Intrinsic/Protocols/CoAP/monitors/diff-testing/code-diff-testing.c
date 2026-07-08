/* CoAP differential-testing RECORDING monitor: request Code.
 *
 * A recording monitor makes ONE request field symbolic, then records the
 * server's response — it never asserts. The verdict is produced offline by the
 * smt-cross-checker. Flow (one KLEE run, state persists across both directions):
 *   1. client request  -> make header.code symbolic ("coap_req_code").
 *   2. server response -> generate_coap_output() records it, then terminate.
 *
 * The symbolic name "coap_req_code" MUST match across the libcoap and FreeCoAP
 * runs, or conjoining their .smt2 files ranges over different input arrays and
 * is meaningless.
 */

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
