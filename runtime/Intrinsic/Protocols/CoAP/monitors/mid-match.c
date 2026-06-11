#include "klee/Protocols/coap/coap_monitors.h"
#include "klee/Protocols/coap/coap_packets.h"
#include "klee/Support/Protocols/helper.h"
#include "klee/klee.h"
#include <assert.h>

/* Requirement (CoAP RFC 7252 §4.2):
 *   "When a Confirmable message is received, the recipient ACK or RST message
 *    MUST echo the Message ID of the Confirmable message."
 *
 * Inject a symbolic Message ID on the request and remember it; if the SUT
 * answers with an ACK or RST, assert its Message ID equals the injected one.
 * Because libcoap copies the MID through, the symbolic value stays a single KLEE
 * path yet proves echo-correctness for all 2^16 values; a server that fails to
 * echo produces a firing path.
 */

#define INIT     0
#define INJECTED 1

static int local_state = INIT;
static uint16_t injected_mid;

void is_coap_mid_matches_request(CoapMessage *message, bool is_message_client_generated)
{
	if (is_message_client_generated && local_state == INIT)
	{
		kleener_make_symbolic(&message->header.message_id,
		                      sizeof(message->header.message_id),
		                      "monitor_mid");
		injected_mid = message->header.message_id;
		local_state = INJECTED;
	}
	else if (!is_message_client_generated && local_state == INJECTED)
	{
		if (message->header.type == COAP_TYPE_ACK ||
		    message->header.type == COAP_TYPE_RST)
		{
			assert(message->header.message_id == injected_mid &&
			       "SUT ACK/RST did not echo the request's Message ID (RFC 7252 §4.2)");
		}
	}
}
