#include "klee/Protocols/coap/coap_monitors.h"
#include "klee/Protocols/coap/coap_packets.h"
#include "klee/Support/Protocols/helper.h"
#include "klee/klee.h"
#include <assert.h>
#include <stddef.h>

/* Requirement (CoAP RFC 7252 §3.1 / §5.4 option format, with the Block2 length
 * bound from RFC 7959 §2.1):
 *   A recognized option carrying a length outside its defined range is a
 *   message-format error. For a *critical* option, a message it cannot be
 *   processed MUST NOT be answered as a successful request — §5.4.1 mandates a
 *   4.02 (Bad Option) for a critical option the recipient cannot handle.
 *
 * Probe: append Block2 (option 23 — critical, odd; valid length 0..3 bytes) with
 * a 4-byte value, which is malformed. A conformant server rejects it (4.02 / a
 * 4.xx error / drop). If libcoap answers 2.xx, it processed a message carrying a
 * malformed critical option as success.
 *
 * Appended (number 23 > the harness request's Uri-Path 11) so the serializer's
 * monotonic delta encoding stays valid. Judge only the first response.
 */

#define INIT     0
#define INJECTED 1
#define DONE     2
#define COAP_OPTION_BLOCK2 23

static int local_state = INIT;
static const uint8_t bad_block[4] = {0x00, 0x00, 0x00, 0x00}; /* 4 bytes > max 3 */

void is_coap_option_length_valid(CoapMessage *message, bool is_message_client_generated)
{
	if (is_message_client_generated && local_state == INIT)
	{
		size_t pos = message->num_options;
		if (pos < COAP_MAX_OPTIONS_LENGTH)
		{
			uint16_t last_number = (pos > 0) ? message->options[pos - 1].number : 0;
			/* Keep the number monotonic; Block2 (23) is already > Uri-Path (11),
			 * but guard in case the request carried a higher option. */
			uint16_t number = COAP_OPTION_BLOCK2;
			if (last_number >= number) number = (uint16_t)((last_number + 1) | 1);

			message->options[pos].number = number;
			message->options[pos].length = sizeof(bad_block); /* 4 — out of range */
			message->options[pos].value  = bad_block;
			message->num_options = pos + 1;
		}
		local_state = INJECTED;
	}
	else if (!is_message_client_generated && local_state == INJECTED)
	{
		local_state = DONE;
		assert(((unsigned)(message->header.code >> 5) != 2) &&
		       "SUT answered 2.xx success to a request carrying a malformed "
		       "critical option (out-of-range Block2 length)");
	}
}
