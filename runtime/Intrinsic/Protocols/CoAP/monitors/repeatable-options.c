#include "klee/Protocols/coap/coap_monitors.h"
#include "klee/Protocols/coap/coap_packets.h"
#include "klee/Support/Protocols/helper.h"
#include "klee/klee.h"
#include <assert.h>
#include <stddef.h>

/* Requirement (CoAP RFC 7252 §5.4.5):
 *   "An Option that is not Repeatable MUST NOT appear more than once in
 *    a message. If the recipient determines that an Option that is not
 *    Repeatable appears more than once in a Request or Response message,
 *    then it MUST be processed as a message format error."
 *
 * Inject a duplicate non-Repeatable option (two extra Accept options, number
 * 17 per RFC §5.10 Table 4) on the request; assert the SUT did not reply with a
 * success response (the PR #1389 bug shape).
 */

#define INIT     0
#define INJECTED 1

static int local_state = INIT;

void is_coap_repeatable_options_valid(CoapMessage *message, bool is_message_client_generated)
{
	if (is_message_client_generated && local_state == INIT)
	{
		/* Append two Accept options (option 17). Accept is odd (critical)
		 * AND non-repeatable per RFC 7252 §5.10 Table 4, so libcoap's
		 * duplicate-non-repeatable check should reject the packet via the
		 * critical-option path, which is what PR #1389 fixed. The on-wire
		 * delta between the two Accepts is 0 and both have length 0 — the
		 * monotonic-delta wire form holds. */
		size_t pos = message->num_options;
		if (pos + 2 <= COAP_MAX_OPTIONS_LENGTH)
		{
			uint16_t last_number = (pos > 0) ? message->options[pos - 1].number : 0;
			uint16_t target = COAP_OPTION_ACCEPT; /* 17 */
			if (last_number > target) target = last_number;

			message->options[pos].number = target;
			message->options[pos].length = 0;
			message->options[pos].value  = NULL;
			message->options[pos + 1].number = target;
			message->options[pos + 1].length = 0;
			message->options[pos + 1].value  = NULL;
			message->num_options = pos + 2;
		}
		local_state = INJECTED;
	}
	else if (!is_message_client_generated && local_state == INJECTED)
	{
		/* PR #1389 bug shape: a server that cannot handle a message carrying
		 * more than one instance of an unrepeatable option proceeds with a
		 * (success) response instead of rejecting it. Fire only on the
		 * success-class response — that is what PR #1389 fixed; a rejection
		 * (no response, or a 4.xx error) never reaches this leg. */
		uint8_t class = (uint8_t)(message->header.code >> 5);
		bool is_success = (class == 2);
		assert(!is_success &&
		       "SUT replied with success to duplicate non-Repeatable option (PR #1389 bug shape)");
	}
}
