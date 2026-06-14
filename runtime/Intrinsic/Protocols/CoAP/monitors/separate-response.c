#include "klee/Protocols/coap/coap_monitors.h"
#include "klee/Protocols/coap/coap_packets.h"
#include "klee/Support/Protocols/helper.h"
#include "klee/klee.h"
#include <stddef.h>

/* Separate-response token matching (CoAP RFC 7252 §5.2.2 + §5.3.2).
 *
 * A "separate" response is not piggybacked in the ACK: the server first ACKs the
 * request (empty ACK), then later sends the response in a NEW message with a
 * DIFFERENT Message ID. The client therefore CANNOT match it by MID — it must
 * match it to the outstanding request BY TOKEN (§5.3.2). This is the companion
 * to the piggybacked-ACK case (exp 11): if libcoap verifies the token here but
 * not on the piggybacked path, the token-spoof finding is sharply "piggybacked
 * only"; if it skips the token here too, the gap is broader.
 *
 * Both monitors reshape the server->client response into a separate-response
 * form: type NON, a fresh Message ID (so it is not a piggyback MID-match), code
 * left at 2.xx. They differ only in the token:
 *   exp 14 (spoof):   flip the token  -> a conformant client MUST drop it.
 *   exp 15 (control): keep the token  -> a conformant client SHOULD deliver it,
 *                     proving the separate path works (so a drop in exp 14 means
 *                     token-checking, not "separate responses ignored").
 *
 * Detection is client-side in the harness response handler (token compared to
 * the one sent). Harness "client got response" in the log == delivered.
 */

static void reshape_to_separate(CoapMessage *message)
{
	message->header.type = COAP_TYPE_CON;             /* not an ACK -> not piggybacked */
	message->header.message_id = (uint16_t)(message->header.message_id + 1); /* fresh MID */
}

/* exp 14 — separate response carrying the WRONG token. */
void is_coap_separate_token_spoof(CoapMessage *message, bool is_message_client_generated)
{
	if (is_message_client_generated)
		return;
	reshape_to_separate(message);
	for (size_t i = 0; i < message->header.token_length &&
	                   i < COAP_MAX_TOKEN_LENGTH; i++)
		message->token[i] ^= 0xFF;
}

/* exp 15 — control: separate response carrying the CORRECT token. */
void is_coap_separate_token_ok(CoapMessage *message, bool is_message_client_generated)
{
	if (is_message_client_generated)
		return;
	reshape_to_separate(message);
	/* token left intact */
}
