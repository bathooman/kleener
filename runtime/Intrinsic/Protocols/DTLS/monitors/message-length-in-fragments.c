#include "klee/Protocols/dtls/dtls_monitors.h"
#include "klee/Protocols/dtls/dtls_records.h"
#include "klee/Support/Protocols/helper.h"
#include "klee/klee.h"
#include <assert.h>

/* Requirement (DTLS 1.2 RFC 6234 Section 4.2.3)
* The length field in all messages is the same as
* the length field of the original message.
*/

/* Discard Requirement (DTLS 1.2 RFC Section 4.1.2.7):
In general, invalid records SHOULD be silently discarded, 
thus preserving the association; however, an error MAY be 
logged for diagnostic purposes.
*/

// monitor states
#define INITIAL 0
#define FIRST_FRAGMENT_RECEIVED 1
#define SECOND_FRAGMENT_RECEIVED 2

static STATE local_state = INITIAL;

static uint8_t handshake_length_f1[HANDSHAKE_LENGTH_LENGTH];
static uint8_t handshake_length_f2[HANDSHAKE_LENGTH_LENGTH];

static bool is_fragment_incomplete(FRAGMENT *fragment) {
    return (byte_to_int(fragment->fragment_length, FRAGMENT_LENGTH_LENGTH) < byte_to_int(fragment->handshake_length, FRAGMENT_LENGTH_LENGTH));
}

void is_message_length_equal_in_fragments_server(RECORD *record, bool is_record_client_generated)
{
    if (is_record_client_generated && local_state == INITIAL)
    {
        /* 
        * We only check this requirement for records for which the epoch is zero.
        * This indirectly ensures that the content of the message is not encrypted.
        * Moreover, this requirement only makes sense for handshake messages.
        * Lastly, we check if the fragment is incomplete.
        */ 
        if (byte_to_int(record->epoch, EPOCH_LENGTH) == 0 && record->content_type == Handshake_REC && 
            is_fragment_incomplete(record->RES.fragment))
        {
            // When the first fragment is received, we only make the message length symbolic
            kleener_make_symbolic(handshake_length_f1, HANDSHAKE_LENGTH_LENGTH, "handshake_length_f1");
            memcpy(record->RES.fragment->handshake_length, handshake_length_f1, HANDSHAKE_LENGTH_LENGTH);
            local_state = FIRST_FRAGMENT_RECEIVED;
        }
    }
    else if (is_record_client_generated && local_state == FIRST_FRAGMENT_RECEIVED)
    {        
        if (byte_to_int(record->epoch, EPOCH_LENGTH) == 0 && record->content_type == Handshake_REC &&
            is_fragment_incomplete(record->RES.fragment))
        {
            // For the second fragment, we make the handshake_length symbolic and assume it 
            // to be unequal to the first fragment's handshake length
            kleener_make_symbolic(handshake_length_f2, HANDSHAKE_LENGTH_LENGTH, "handshake_length_f2");
            memcpy(record->RES.fragment->handshake_length, handshake_length_f2, HANDSHAKE_LENGTH_LENGTH);
            klee_assume(byte_to_int(handshake_length_f1, HANDSHAKE_LENGTH_LENGTH) != 
                        byte_to_int(handshake_length_f2, HANDSHAKE_LENGTH_LENGTH));
            
            local_state = SECOND_FRAGMENT_RECEIVED;
        }
    }
    else if (!is_record_client_generated && local_state == SECOND_FRAGMENT_RECEIVED)
    {   
        // A failed assertion is enabled in the case we receive a response other than an Alert
        if (record->content_type != Alert_REC)
            kleener_assert("Invalid Message Length");
    }
}

void is_message_length_equal_in_fragments_client(RECORD *record, bool is_record_client_generated)
{
    if (!is_record_client_generated && local_state == INITIAL)
    {
        if (byte_to_int(record->epoch, EPOCH_LENGTH) == 0 && record->content_type == Handshake_REC && 
            is_fragment_incomplete(record->RES.fragment))
        {
            kleener_make_symbolic(handshake_length_f1, HANDSHAKE_LENGTH_LENGTH, "handshake_length_f1");
            memcpy(record->RES.fragment->handshake_length, handshake_length_f1, HANDSHAKE_LENGTH_LENGTH);
            local_state = FIRST_FRAGMENT_RECEIVED;
        }
    }
    else if (!is_record_client_generated && local_state == FIRST_FRAGMENT_RECEIVED)
    {   
        if (byte_to_int(record->epoch, EPOCH_LENGTH) == 0 && record->content_type == Handshake_REC &&
            is_fragment_incomplete(record->RES.fragment))
        {
            kleener_make_symbolic(handshake_length_f2, HANDSHAKE_LENGTH_LENGTH, "handshake_length_f2");
            memcpy(record->RES.fragment->handshake_length, handshake_length_f2, HANDSHAKE_LENGTH_LENGTH);
            klee_assume(byte_to_int(handshake_length_f1, HANDSHAKE_LENGTH_LENGTH) != 
                        byte_to_int(handshake_length_f2, HANDSHAKE_LENGTH_LENGTH));
            
            local_state = SECOND_FRAGMENT_RECEIVED;
        }
    }
    else if (is_record_client_generated && local_state == SECOND_FRAGMENT_RECEIVED)
    {
        if (record->content_type != Alert_REC)
            kleener_assert("Invalid Message Length");
    }
}