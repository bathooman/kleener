#include "klee/Protocols/coap/coap_monitors.h"
#include "klee/Protocols/coap/coap_packets.h"
#include "klee/Support/Protocols/helper.h"
#include "klee/klee.h"
#include <assert.h>
#include <string.h>

/* Requirement (CoAP RFC 7252 §5.3.1):
 *   "Every request carries a client-generated token that the server MUST echo
 *    (without modification) in any resulting response."
 *
 * Requires the harness request to carry a non-empty token (added via
 * coap_add_token); an empty token has nothing to echo and the monitor no-ops.
 * Inject symbolic token bytes while keeping the original TKL (so the
 * shadow-bounded copy stays safe); on a response (code class 2/4/5) assert its
 * token equals the injected one. A conformant server echoes verbatim on every
 * path; one that drops or mangles the token fires.
 */

#define INIT     0
#define INJECTED 1

static int     local_state = INIT;
static uint8_t injected_token[COAP_MAX_TOKEN_LENGTH];
static uint8_t injected_tkl;

void is_coap_token_matches_request(CoapMessage *message, bool is_message_client_generated)
{
	if (is_message_client_generated && local_state == INIT)
	{
		uint8_t tkl = message->header.token_length;
		if (tkl > COAP_MAX_TOKEN_LENGTH) tkl = COAP_MAX_TOKEN_LENGTH;
		if (tkl > 0)
		{
			kleener_make_symbolic(message->token, tkl, "monitor_token");
			memcpy(injected_token, message->token, tkl);
		}
		injected_tkl = tkl;
		local_state = INJECTED;
	}
	else if (!is_message_client_generated && local_state == INJECTED)
	{
		uint8_t class = (uint8_t)(message->header.code >> 5);
		if (class != 2 && class != 4 && class != 5)
			return;
		if (injected_tkl == 0)
			return;

		assert(message->header.token_length == injected_tkl &&
		       memcmp(message->token, injected_token, injected_tkl) == 0 &&
		       "SUT response did not echo the request token (RFC 7252 §5.3.1)");
	}
}
