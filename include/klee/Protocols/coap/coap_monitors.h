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
#define coap_token_spoof_requirement 11
#define coap_option_length_requirement 12
#define coap_payload_marker_requirement 13
#define coap_separate_token_spoof_requirement 14
#define coap_separate_token_ok_requirement 15
#define coap_mid_spoof_requirement 17

/* ---- Differential-testing RECORDING monitor IDs ----
 * Numbered from 100 to stay clear of the conformance-monitor range above. A
 * recording monitor makes one request field symbolic and records the server's
 * response via generate_coap_output; the verdict is produced offline by the
 * smt-cross-checker, not by an assert. Each monitor names its symbolic field
 * "coap_req_*"; that name MUST match across the two implementation runs, or
 * conjoining their .smt2 constraints ranges over different arrays and means
 * nothing.
 */
#define coap_code_diff_test 100
#define coap_version_diff_test 101
#define coap_type_diff_test 102
#define coap_token_length_diff_test 103
#define coap_mid_diff_test 104
#define coap_type_code_diff_test 105

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

/* Client-side: corrupt the response token (RFC 7252 §5.3.2). Detection is in
 * the harness response handler — a conformant client drops the mismatched
 * response. */
void is_coap_token_spoofable(CoapMessage *message, bool is_message_client_generated);

/* Server-side: append a malformed (out-of-range length) critical option and
 * assert the server does not answer 2.xx success (RFC 7252 §5.4.1 / RFC 7959). */
void is_coap_option_length_valid(CoapMessage *message, bool is_message_client_generated);

/* Server-side: attach a dangling payload marker (0xFF + zero-length payload) and
 * assert the server does not answer 2.xx success (RFC 7252 §3.1). */
void is_coap_payload_marker_valid(CoapMessage *message, bool is_message_client_generated);

/* Client-side separate-response token matching (RFC 7252 §5.2.2/§5.3.2): reshape
 * the response to a separate form (NON, fresh MID); exp 14 corrupts the token,
 * exp 15 keeps it as a control. Detection is in the harness response handler. */
void is_coap_separate_token_spoof(CoapMessage *message, bool is_message_client_generated);
void is_coap_separate_token_ok(CoapMessage *message, bool is_message_client_generated);

/* Client-side dual of token-spoof (RFC 7252 §5.3.2): flip the response's
 * Message ID while keeping the token correct, to observe whether libcoap
 * discards a wrong-MID response or still delivers it. Detection is in the
 * harness response handler. */
void is_coap_mid_spoofable(CoapMessage *message, bool is_message_client_generated);

/* ---- Differential-testing recording monitors ----
 * Each makes one request field symbolic, then calls generate_coap_output (see
 * coap_packets.h) on the response to record the output schema. */
void code_diff_testing_server(CoapMessage *message, bool is_message_client_generated);
void version_diff_testing_server(CoapMessage *message, bool is_message_client_generated);
void type_diff_testing_server(CoapMessage *message, bool is_message_client_generated);
void token_length_diff_testing_server(CoapMessage *message, bool is_message_client_generated);

/* Makes the request Message ID symbolic (coap_req_mid) and records the response
 * including responseMessageId, to expose divergences in how servers echo the
 * Message ID in their reply (RFC 7252 §4.2). */
void mid_diff_testing_server(CoapMessage *message, bool is_message_client_generated);

/* Makes request type AND code symbolic to explore the type-x-code acceptance
 * matrix (RFC 7252 §§4.1-4.3); subsumes the Empty-message requirement. */
void type_code_diff_testing_server(CoapMessage *message, bool is_message_client_generated);

#endif
