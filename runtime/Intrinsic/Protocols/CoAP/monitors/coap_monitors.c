/* CoAP monitor dispatcher.
 *
 * The contract is:
 *
 *   handle_coap_message(in, in_size, out, out_size, is_client_originated, monitor)
 *
 * 1. Parse `in` into a mutable CoapMessage `msg` AND an immutable shadow
 *    (concrete sizes used by the serializer when the live message's
 *    fields go symbolic).
 * 2. Invoke `monitor.handle(&msg, is_client_originated)`. The monitor
 *    may make fields of `msg` symbolic and `klee_assume` constraints on
 *    them, then assert the requirement.
 * 3. Serialize the (possibly mutated) `msg` back into `out`. The SUT
 *    then parses `out` — so byte-level mutations made by the monitor
 *    actually reach libcoap, not just our framework's view.
 */

#include "klee/Protocols/coap/coap_monitors.h"
#include "klee/Protocols/coap/coap_packets.h"
#include <stddef.h>
#include <string.h>
#include <stdio.h>

coap_monitor_handle set_coap_monitor_handle(int experiment, SIDE side_to_check)
{
    static const struct entry {
        coap_monitor_handle server_mon;
        coap_monitor_handle client_mon;
    } table[] = {
        [coap_normal_execution]              = {NULL, NULL},
        [coap_version_requirement]           = {is_coap_version_valid,            is_coap_version_valid},
        [coap_token_length_requirement]      = {is_coap_token_length_valid,       is_coap_token_length_valid},
        [coap_code_requirement]              = {is_coap_code_valid,               is_coap_code_valid},
        [coap_empty_message_requirement]     = {is_coap_empty_message_valid,      is_coap_empty_message_valid},
        [coap_mid_match_requirement]         = {is_coap_mid_matches_request,      is_coap_mid_matches_request},
        [coap_token_match_requirement]       = {is_coap_token_matches_request,    is_coap_token_matches_request},
        [coap_matching_type_requirement]     = {is_coap_matching_message_type,    is_coap_matching_message_type},
        [coap_repeatable_opts_requirement]   = {is_coap_repeatable_options_valid, is_coap_repeatable_options_valid},
        [coap_unrecognized_opts_requirement] = {is_coap_unrecognized_options_valid, is_coap_unrecognized_options_valid},
        [coap_token_spoof_requirement]       = {is_coap_token_spoofable,           is_coap_token_spoofable},
        [coap_option_length_requirement]     = {is_coap_option_length_valid,       is_coap_option_length_valid},
        [coap_payload_marker_requirement]    = {is_coap_payload_marker_valid,      is_coap_payload_marker_valid},
        [coap_separate_token_spoof_requirement] = {is_coap_separate_token_spoof,   is_coap_separate_token_spoof},
        [coap_separate_token_ok_requirement]    = {is_coap_separate_token_ok,      is_coap_separate_token_ok},
        [coap_mid_spoof_requirement]            = {is_coap_mid_spoofable,          is_coap_mid_spoofable},
    };

    if (experiment < 0 || experiment > coap_mid_spoof_requirement)
        return NULL;

    const struct entry *e = &table[experiment];
    if (side_to_check == CLIENT) return e->client_mon;
    if (side_to_check == SERVER) return e->server_mon;
    return e->server_mon;
}

int handle_coap_message(const uint8_t *in, size_t in_size,
                        uint8_t *out, size_t out_size,
                        bool is_client_originated,
                        COAP_MONITOR mon)
{
    CoapMessage msg;
    CoapMessage shadow;

    memset(&msg,    0, sizeof(msg));
    memset(&shadow, 0, sizeof(shadow));

    if (parse_coap_message(in, in_size, &msg) != 0)
        return -1;
    if (parse_coap_message(in, in_size, &shadow) != 0)
        return -1;

    if (mon.handle != NULL)
        mon.handle(&msg, is_client_originated);

    /* Return the number of bytes written to `out` — the monitor may have
     * resized the message — or -1 on parse/serialize failure. */
    return serialize_coap_message(&msg, &shadow, out, out_size);
}
