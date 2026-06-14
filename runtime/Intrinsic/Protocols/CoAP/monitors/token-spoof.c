#include "klee/Protocols/coap/coap_monitors.h"
#include "klee/Protocols/coap/coap_packets.h"
#include "klee/Support/Protocols/helper.h"
#include "klee/klee.h"
#include <stddef.h>

/* Requirement (CoAP RFC 7252 §5.3.2, Request/Response Matching):
 *   "For a piggybacked response, ... the Message ID of the Confirmable
 *    request and the Acknowledgement MUST match, and the tokens of the
 *    response and original request MUST match."
 *
 * The existing token-match monitor (exp 7) checks the SERVER echoes the token.
 * This is the CLIENT-side dual, and the security-relevant one (RFC 7252 §11.4,
 * response spoofing): a client MUST reject a response whose token does not
 * match an outstanding request. A 16-bit Message ID is far easier for an
 * attacker to guess/observe than the token, so if a client accepts a
 * piggybacked ACK on a MID match alone — ignoring a wrong token — an off-path
 * attacker can inject a forged response.
 *
 * Injection: on the server->client response only, corrupt the token (flip every
 * byte) while leaving type/code/MID intact, so the datagram is still a valid
 * piggybacked ACK that MID-matches the request but carries the wrong token.
 *
 * Detection is on the client side, in the harness response handler: if libcoap
 * still delivers this response to the application, it matched by MID alone.
 * A conformant client drops it (handler never fires) — which correctly shows
 * up as "no fire" here.
 */
void is_coap_token_spoofable(CoapMessage *message, bool is_message_client_generated)
{
	/* Leave the client's request untouched so the server echoes the real
	 * token; only corrupt the response on its way back to the client. */
	if (is_message_client_generated)
		return;

	for (size_t i = 0; i < message->header.token_length && i < COAP_MAX_TOKEN_LENGTH; i++)
		message->token[i] ^= 0xFF;   /* guaranteed != the request's token */
}
