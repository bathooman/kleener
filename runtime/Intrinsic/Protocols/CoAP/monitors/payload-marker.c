#include "klee/Protocols/coap/coap_monitors.h"
#include "klee/Protocols/coap/coap_packets.h"
#include "klee/Support/Protocols/helper.h"
#include "klee/klee.h"
#include <assert.h>
#include <stddef.h>

/* Requirement (CoAP RFC 7252 §3.1):
 *   "The presence of a marker followed by a zero-length payload MUST be
 *    processed as a message format error."
 *
 * Probe: on the request, attach a dangling payload marker (0xFF with no payload
 * bytes after it) by setting a non-NULL payload pointer with payload_length 0;
 * the (patched) serializer emits the bare marker. A conformant server treats
 * this as a format error (4.00 Bad Request / drop / RST). If libcoap answers
 * 2.xx, it processed a malformed message as a successful request.
 */

#define INIT     0
#define INJECTED 1
#define DONE     2

static int local_state = INIT;
static const uint8_t dummy = 0x00;   /* non-NULL sentinel; no bytes are emitted */

void is_coap_payload_marker_valid(CoapMessage *message, bool is_message_client_generated)
{
	if (is_message_client_generated && local_state == INIT)
	{
		message->payload = &dummy;       /* non-NULL ... */
		message->payload_length = 0;     /* ... with zero length => bare 0xFF */
		local_state = INJECTED;
	}
	else if (!is_message_client_generated && local_state == INJECTED)
	{
		local_state = DONE;
		assert(((unsigned)(message->header.code >> 5) != 2) &&
		       "SUT answered 2.xx success to a message with a dangling payload "
		       "marker / zero-length payload (RFC 7252 3.1 format error)");
	}
}
