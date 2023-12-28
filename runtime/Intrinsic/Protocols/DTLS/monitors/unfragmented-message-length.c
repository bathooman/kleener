#include "klee/Protocols/dtls/dtls_monitors.h"
#include "klee/Protocols/dtls/dtls_records.h"
#include "klee/Support/Protocols/helper.h"
#include "klee/klee.h"
#include <assert.h>

/* Requirement (DTLS 1.2 RFC 6347 Section 4.2.3)
* An unfragmented message is a degenerate case with
* fragment_offset=0 and fragment_length=length.
*/

/* Discard Requirement (DTLS 1.2 RFC Section 4.1.2.7):
In general, invalid records SHOULD be silently discarded, 
thus preserving the association; however, an error MAY be 
logged for diagnostic purposes.
*/

#define INITIAL 0
#define RECORD_RECEIVED 1

static STATE local_state = INITIAL;

static bool is_fragment_complete(FRAGMENT *fragment) {
    return (byte_to_int(fragment->fragment_length, FRAGMENT_LENGTH_LENGTH) == byte_to_int(fragment->handshake_length, FRAGMENT_LENGTH_LENGTH));
}

void is_unfragmented_message_length_valid_server(RECORD *record, bool is_record_client_generated)
{
    if (is_record_client_generated && local_state == INITIAL)
    {
        /* 
        * We only check this requirement for records for which the epoch is zero.
        * This indirectly ensures that the content of the message is not encrypted.
        * Moreover, this requirement only makes sense for handshake messages.
        * Lastly, we check if the fragment is complete.
        */ 
        if (record->content_type == Handshake_REC && byte_to_int(record->epoch, EPOCH_LENGTH) == 0 
            && is_fragment_complete(record->RES.fragment))
        {
            // Fragment_length and Handshake_length are both made symbolic and assumed to unequal
            kleener_make_symbolic(record->RES.fragment->fragment_length, FRAGMENT_LENGTH_LENGTH, "fragment_length");
            kleener_make_symbolic(record->RES.fragment->handshake_length, HANDSHAKE_LENGTH_LENGTH, "handshake_length");
            klee_assume(byte_to_int(record->RES.fragment->fragment_length, FRAGMENT_LENGTH_LENGTH) != 
                        byte_to_int(record->RES.fragment->handshake_length, HANDSHAKE_LENGTH_LENGTH));

            local_state = RECORD_RECEIVED;
        }
    }
    else if (!is_record_client_generated && local_state == RECORD_RECEIVED)
    {
        // Failed assertion if we receive a response to an invalid record
        if (record->content_type != Alert_REC)
            kleener_assert("Invalid fragment offset");
    }
}

void is_unfragmented_message_length_valid_client(RECORD *record, bool is_record_client_generated)
{
    if (!is_record_client_generated && local_state == INITIAL)
    {
        if (record->content_type == Handshake_REC && byte_to_int(record->epoch, EPOCH_LENGTH) == 0 
            && is_fragment_complete(record->RES.fragment))
        {
            kleener_make_symbolic(record->RES.fragment->fragment_length, FRAGMENT_LENGTH_LENGTH, "fragment_length");
            kleener_make_symbolic(record->RES.fragment->handshake_length, HANDSHAKE_LENGTH_LENGTH, "handshake_length");
            klee_assume(byte_to_int(record->RES.fragment->fragment_length, FRAGMENT_LENGTH_LENGTH) != 
                        byte_to_int(record->RES.fragment->handshake_length, HANDSHAKE_LENGTH_LENGTH));

            local_state = RECORD_RECEIVED;
        }
    }
    else if (is_record_client_generated && local_state == RECORD_RECEIVED)
    {
        if (record->content_type != Alert_REC)
            kleener_assert("Invalid fragment offset");
    }
}