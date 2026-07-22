#include "klee/Protocols/coap/coap_monitors.h"
#include "klee/Protocols/coap/coap_packets.h"
#include "klee/Support/Protocols/helper.h"
#include "klee/klee.h"
#include <assert.h>

/* Requirement (CoAP RFC 7252 §4.1):
 *   "An Empty message has the Code field set to 0.00. The Token Length
 *    field MUST be set to 0 and bytes of data MUST NOT be present after
 *    the Message ID field. If there are any bytes, they MUST be processed
 *    as a message format error."
 *
 * Inject an Empty code (0.00) with a non-zero TKL (1-8) — malformed per the
 * rule above; assert the SUT replied with an empty RST.
 */

#define INIT     0
#define INJECTED 1

static int local_state = INIT;

void is_coap_empty_message_valid(CoapMessage *message, bool is_message_client_generated)
{
	if (is_message_client_generated && local_state == INIT)
	{
		message->header.code = COAP_CODE_EMPTY;
		kleener_make_symbolic(&message->header.token_length,
		                      sizeof(message->header.token_length),
		                      "monitor_empty_tkl");
		klee_assume(message->header.token_length >= 1);
		klee_assume(message->header.token_length <= 8);
		local_state = INJECTED;
	}
	else if (!is_message_client_generated && local_state == INJECTED)
	{
		bool is_rst   = (message->header.type == COAP_TYPE_RST);
		bool is_empty = (message->header.code == 0);
		assert((is_rst && is_empty) &&
		       "SUT responded to a malformed Empty message (Code=0 but TKL>0)");
	}
}
