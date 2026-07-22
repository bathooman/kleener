#include "klee/Protocols/coap/coap_monitors.h"
#include "klee/Protocols/coap/coap_packets.h"
#include "klee/Support/Protocols/helper.h"
#include "klee/klee.h"
#include <assert.h>

/* Requirement (CoAP RFC 7252 §3):
 *   Token Length (TKL): 4-bit unsigned integer; valid range 0–8.
 *   Lengths 9–15 are reserved and MUST be processed as a message
 *   format error.
 *
 * Inject a reserved TKL (9-15) on the request. The mandated reaction to a
 * format error on a CON is a matching empty RST (RFC 7252 §4.2), so a conformant
 * server either sends that RST or silently drops the message (the response
 * branch is then never reached). Any other response means the server processed
 * the malformed framing — that is the violation we fire on.
 *
 * Note: because the serializer writes the live TKL (9-15) into the header nibble
 * but copies only the shadow's original token bytes, the datagram claims more
 * token bytes than it carries — exercising the parser's TKL-vs-length check.
 */

#define INIT     0
#define INJECTED 1

static int local_state = INIT;

void is_coap_token_length_valid(CoapMessage *message, bool is_message_client_generated)
{
	if (is_message_client_generated && local_state == INIT)
	{
		/* TKL is a 4-bit field — constrain symbolic value to the reserved
		 * range [9, 15]. */
		kleener_make_symbolic(&message->header.token_length,
		                      sizeof(message->header.token_length),
		                      "monitor_tkl");
		klee_assume(message->header.token_length >= 9);
		klee_assume(message->header.token_length <= 15);
		local_state = INJECTED;
	}
	else if (!is_message_client_generated && local_state == INJECTED)
	{
		bool is_rst   = (message->header.type == COAP_TYPE_RST);
		bool is_empty = (message->header.code == 0);
		assert((is_rst && is_empty) &&
		       "SUT did not reject a reserved-TKL (9-15) message with an empty RST (RFC 7252 §3/§4.2 format error)");
	}
}
