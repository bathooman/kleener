#include "klee/Protocols/dtls/dtls_monitors.h"
#include "klee/Protocols/dtls/dtls_records.h"
#include "klee/Support/Protocols/helper.h"
#include "klee/klee.h"
#include <assert.h>

/* Requirement (DTLS 1.2 RFC 6234 Section 4.2.3)
* The sender then creates N handshake messages, all with the
* same message_seq value as the original handshake message.
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

static uint8_t message_seq_f1[MESSAGE_SEQ_LENGTH];
static uint8_t message_seq_f2[MESSAGE_SEQ_LENGTH];

static bool is_message_seq_equal(uint8_t  *message_seq_f1, uint8_t* message_seq_f2) {
    return (byte_to_int(message_seq_f1, MESSAGE_SEQ_LENGTH) == byte_to_int(message_seq_f2, MESSAGE_SEQ_LENGTH));
}

static bool is_fragment_incomplete(FRAGMENT *fragment) {
    return (byte_to_int(fragment->fragment_length, FRAGMENT_LENGTH_LENGTH) < byte_to_int(fragment->handshake_length, FRAGMENT_LENGTH_LENGTH));
}

void is_message_seq_equal_in_fragments_server(RECORD *record, bool is_record_client_generated) 
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
            // When the first fragment is received, we only make the message sequence symbolic
            kleener_make_symbolic(message_seq_f1, MESSAGE_SEQ_LENGTH, "message_seq_f1");
            memcpy(record->RES.fragment->message_sequence, message_seq_f1, MESSAGE_SEQ_LENGTH);
            local_state = FIRST_FRAGMENT_RECEIVED;
        }        
    }
    else if (is_record_client_generated && local_state == FIRST_FRAGMENT_RECEIVED)
    {
        if (byte_to_int(record->epoch, EPOCH_LENGTH) == 0 && record->content_type == Handshake_REC &&
            is_fragment_incomplete(record->RES.fragment))
        {
            // When the second fragment is received, we make the message sequence symbolic and assume
            // it to be unequal to the first fragment's message sequence. Since, we perform the fragmentation
            // of the messages in our framework, it is safe to assume that we only have two fragments.
            kleener_make_symbolic(message_seq_f2, MESSAGE_SEQ_LENGTH, "message_seq_f2");
            memcpy(record->RES.fragment->message_sequence, message_seq_f2, MESSAGE_SEQ_LENGTH);
            klee_assume(!is_message_seq_equal(message_seq_f1, message_seq_f2));
            local_state = SECOND_FRAGMENT_RECEIVED;
        }
        
    }
    else if (!is_record_client_generated && local_state == SECOND_FRAGMENT_RECEIVED)
    {
        // A failed assertion is enabled in the case we receive a response other than an Alert
        if (record->content_type != Alert_REC)
            kleener_assert("Invalid Message Sequence");
    }

}


void is_message_seq_equal_in_fragments_client(RECORD *record, bool is_record_client_generated) 
{
    if (!is_record_client_generated && local_state == INITIAL)
    {
        if (byte_to_int(record->epoch, EPOCH_LENGTH) == 0 && record->content_type == Handshake_REC && 
            is_fragment_incomplete(record->RES.fragment))
        {
            kleener_make_symbolic(message_seq_f1, MESSAGE_SEQ_LENGTH, "message_seq_f1");
            memcpy(record->RES.fragment->message_sequence, message_seq_f1, MESSAGE_SEQ_LENGTH);
            local_state = FIRST_FRAGMENT_RECEIVED;
        } 
    }
    else if (!is_record_client_generated && local_state == FIRST_FRAGMENT_RECEIVED)
    {
        if (byte_to_int(record->epoch, EPOCH_LENGTH) == 0 && record->content_type == Handshake_REC &&
            is_fragment_incomplete(record->RES.fragment))
        {
            kleener_make_symbolic(message_seq_f2, MESSAGE_SEQ_LENGTH, "message_seq_f2");
            memcpy(record->RES.fragment->message_sequence, message_seq_f2, MESSAGE_SEQ_LENGTH);
            klee_assume(!is_message_seq_equal(message_seq_f1, message_seq_f2));
            local_state = SECOND_FRAGMENT_RECEIVED;
        }
    }
    else if (is_record_client_generated && local_state == SECOND_FRAGMENT_RECEIVED)
    {
        if (record->content_type != Alert_REC)
            kleener_assert("Invalid Message Sequence");
    }
}


