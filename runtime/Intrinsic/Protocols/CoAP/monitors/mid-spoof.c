#include "klee/Protocols/coap/coap_monitors.h"
#include "klee/Protocols/coap/coap_packets.h"
#include "klee/Support/Protocols/helper.h"
#include "klee/klee.h"
#include <stddef.h>

/* Dual of the token-spoof monitor (exp 11). RFC 7252 §5.3.2 requires a
 * piggybacked response to match the request on BOTH Message ID AND token.
 * exp 11 showed libcoap ignores the token (wrong token + right MID => still
 * matched). This monitor tests the other axis: keep the token CORRECT, flip the
 * Message ID, and observe whether libcoap discards the response (no MID match)
 * or still delivers it. If matching is MID-keyed (as exp 11 implies), the
 * wrong-MID response finds no outstanding request and is dropped — the harness
 * response handler then never fires. Together the two experiments pin the match
 * function down to "Message ID alone".
 *
 * Injection: server->client response only; flip all 16 bits of the Message ID
 * (guaranteed != the request's MID) while leaving type/code/token intact, so the
 * datagram is still a well-formed piggybacked ACK carrying the real token.
 *
 * Detection is on the client side, in the harness response handler (gated on the
 * experiment id): it logs whether the handler fired and whether sent != NULL.
 * Delivery as MATCHED (sent != NULL) despite the wrong MID would be a second,
 * separate defect; a plain drop (handler never fires) is the expected result.
 */
void is_coap_mid_spoofable(CoapMessage *message, bool is_message_client_generated)
{
	/* Only corrupt the response on its way back to the client; leave the
	 * client's request (and its token) untouched. */
	if (is_message_client_generated)
		return;

	message->header.message_id ^= 0xFFFF;   /* guaranteed != the request's MID */
}
