#include "klee/Protocols/coap/coap_monitors.h"
#include "klee/Protocols/coap/coap_packets.h"
#include "klee/Support/Protocols/helper.h"
#include "klee/klee.h"
#include <assert.h>

/* Requirement (CoAP RFC 7252 §3 + §12.1):
 *   Code = 3-bit class (c) | 5-bit detail (dd).
 *   Defined classes: 0 (request), 2 (success), 4 (client error), 5 (server error).
 *   Classes 1, 6, 7 are reserved and MUST NOT be used.
 *
 * Inject a Code byte whose class is reserved (1, 6, or 7); assert the SUT
 * replied with an empty RST.
 */

#define INIT     0
#define INJECTED 1

static int local_state = INIT;

void is_coap_code_valid(CoapMessage *message, bool is_message_client_generated)
{
	if (is_message_client_generated && local_state == INIT)
	{
		kleener_make_symbolic(&message->header.code,
		                      sizeof(message->header.code),
		                      "monitor_code");
		uint8_t class = (uint8_t)(message->header.code >> 5);
		klee_assume(class == 1 || class == 6 || class == 7);
		local_state = INJECTED;
	}
	else if (!is_message_client_generated && local_state == INJECTED)
	{
		bool is_rst   = (message->header.type == COAP_TYPE_RST);
		bool is_empty = (message->header.code == 0);
		assert((is_rst && is_empty) &&
		       "SUT responded to a CoAP message with reserved code class (1/6/7)");
	}
}
