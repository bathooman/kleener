#include "klee/Protocols/coap/coap_monitors.h"
#include "klee/Protocols/coap/coap_packets.h"
#include "klee/Support/Protocols/helper.h"
#include "klee/klee.h"
#include <assert.h>
#include <stddef.h>

/* Requirement (CoAP RFC 7252 §5.4.1):
 *   "Unrecognized options of class 'critical' that occur in a
 *    Confirmable request MUST cause the return of a 4.02 (Bad Option)
 *    response. Unrecognized options of class 'elective' MUST be silently
 *    ignored."
 *
 * Critical = bit 0 of option number is set (odd number).
 *
 * Inject a single unknown Critical option (number 21 — odd, unassigned) on the
 * request; assert the first response is 4.02 Bad Option (code 0x82, the reaction
 * §5.4.1 mandates). The DONE state ensures only the first response is judged.
 */

#define INIT     0
#define INJECTED 1
#define DONE     2
#define COAP_CODE_BAD_OPTION 0x82  /* 4.02 — class 4, detail 2 */

static int local_state = INIT;

void is_coap_unrecognized_options_valid(CoapMessage *message, bool is_message_client_generated)
{
	if (is_message_client_generated && local_state == INIT)
	{
		size_t pos = message->num_options;
		if (pos < COAP_MAX_OPTIONS_LENGTH)
		{
			uint16_t last_number = (pos > 0) ? message->options[pos - 1].number : 0;
			uint16_t target = 21; /* odd, unassigned, monotonic-friendly */
			/* Must stay > last_number AND odd (critical = bit 0 set). Plain
			 * last_number+2 inherits last_number's parity, so an even
			 * predecessor would yield an even (elective) number and silently
			 * stop exercising the critical-option path. (n+1)|1 is the
			 * smallest odd strictly greater than n. */
			if (last_number >= target) target = (uint16_t)((last_number + 1) | 1);

			message->options[pos].number = target;
			message->options[pos].length = 0;
			message->options[pos].value  = NULL;
			message->num_options = pos + 1;
		}
		local_state = INJECTED;
	}
	else if (!is_message_client_generated && local_state == INJECTED)
	{
		/* Judge only the first response, then stop — otherwise a later packet
		 * (e.g. a piggybacked 2.05 following the correct 4.02) would re-trip the
		 * assertion. A silent drop is caught separately by coap_exchange_finalize. */
		local_state = DONE;
		assert(message->header.code == COAP_CODE_BAD_OPTION &&
		       "SUT did not return 4.02 Bad Option for unrecognized critical option");
	}
}
