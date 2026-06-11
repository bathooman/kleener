#ifndef COAP_MONITORS_H
#define COAP_MONITORS_H

#include <stdbool.h>
#include "klee/Protocols/coap/coap_packets.h"
#include "klee/Support/Protocols/helper.h"   /* SIDE enum, which_side_checked */

#define COAP_VERSION 1

/* ---- Requirement IDs ----
 * Also the legal values of KLEE_SYMBOLIC_EXPERIMENT: the runner passes one
 * through and the dispatcher selects the matching monitor.
 */
#define coap_normal_execution            0
#define coap_version_requirement         1
#define coap_token_length_requirement    2
#define coap_code_requirement            3
#define coap_empty_message_requirement   4
#define coap_mid_match_requirement       6
#define coap_token_match_requirement     7
#define coap_matching_type_requirement   8
#define coap_repeatable_opts_requirement 9
#define coap_unrecognized_opts_requirement 10

/* ---- Monitor dispatch table ----
 * One monitor handle per (requirement, side). Every requirement currently
 * registers the same handle for both sides, since CoAP requirements are
 * largely direction-agnostic; the per-side slot lets a monitor that must
 * distinguish client from server diverge without changing this interface.
 */
typedef void (*coap_monitor_handle)(CoapMessage *message, bool is_message_client_generated);

typedef struct
{
    coap_monitor_handle handle;
} COAP_MONITOR;

coap_monitor_handle set_coap_monitor_handle(int experiment, SIDE side_to_check);

/* Parse `in` into a CoapMessage, invoke `mon.handle`, then write the
 * (possibly mutated) message back into `out`.
 * Returns the number of bytes written to `out` (>= 4) on success, or -1 on
 * failure — the monitor may resize the message, so the caller must use this
 * length, not in_size. */
int handle_coap_message(const uint8_t *in, size_t in_size,
                        uint8_t *out, size_t out_size,
                        bool is_client_originated, COAP_MONITOR mon);

void is_coap_version_valid(CoapMessage *message, bool is_message_client_generated);

void is_coap_token_length_valid(CoapMessage *message, bool is_message_client_generated);

void is_coap_code_valid(CoapMessage *message, bool is_message_client_generated);

void is_coap_empty_message_valid(CoapMessage *message, bool is_message_client_generated);

/* Inject-then-assert: inject a symbolic Message ID into the request, assert the
 * SUT's ACK/RST echoes it (RFC 7252 §4.2). */
void is_coap_mid_matches_request(CoapMessage *message, bool is_message_client_generated);

/* Inject-then-assert: inject a symbolic token into the request, assert the SUT's
 * response echoes it verbatim (RFC 7252 §5.3.1). */
void is_coap_token_matches_request(CoapMessage *message, bool is_message_client_generated);

/* Single-message structural monitor: (type, code) tuple must satisfy the matrix
   in RFC 7252 §§4.1-4.3 — CON/NON/ACK/RST each restrict which code classes are
   admissible. */
void is_coap_matching_message_type(CoapMessage *message, bool is_message_client_generated);

/* Single-message structural monitor: non-Repeatable options
   (RFC 7252 §5.10 Table 4 / §5.4.5) must appear ≤ 1 time in a message. */
void is_coap_repeatable_options_valid(CoapMessage *message, bool is_message_client_generated);

/* Inject-then-assert: append an unrecognized Critical option (odd number) to
   the request, assert the SUT returns 4.02 Bad Option (RFC 7252 §5.4.1). */
void is_coap_unrecognized_options_valid(CoapMessage *message, bool is_message_client_generated);

#endif
