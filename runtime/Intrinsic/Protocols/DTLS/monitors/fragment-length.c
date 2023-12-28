#include "klee/Protocols/dtls/dtls_monitors.h"
#include "klee/Protocols/dtls/dtls_records.h"
#include "klee/klee.h"
#include <assert.h>

/* Requirement (DTLS 1.2 RFC Section 4.2.3)
* Each new message is labeled with the fragment_offset (the number of bytes
* contained in previous fragments) and the fragment_length (the length
* of this fragment).
*/


/* Discard Requirement (DTLS 1.2 RFC Section 4.1.2.7):
In general, invalid records SHOULD be silently discarded, 
thus preserving the association; however, an error MAY be 
logged for diagnostic purposes.
*/

/*
* For checking the validity of each length field, We make use of the concrete value of the field.
* Since we successfully parsed the received datagram into RECORD data structures, it is safe to 
* assume that the concrete value for each length field in the RECORD structure is valid.
*/

#define INITIAL 0
#define RECORD_RECEIVED 1

static STATE local_state = INITIAL;

void is_fragment_length_valid_server(RECORD *record, bool is_record_client_generated)
{
    if (is_record_client_generated && local_state == INITIAL)
    {
        /* 
        * We only check this requirement for records for which the epoch is zero.
        * This indirectly ensures that the content of the message is not encrypted.
        * Moreover, this requirement only makes sense for handshake messages.
        */ 
        if (record->content_type == Handshake_REC && byte_to_int(record->epoch, EPOCH_LENGTH) == 0)
        {
            // The concrete value is stored as the valid value
            uint16_t valid_fragment_length = byte_to_int(record->RES.fragment->fragment_length, FRAGMENT_LENGTH_LENGTH);

            // Fragment length is made symbolic and assumed to be invalid
            kleener_make_symbolic(record->RES.fragment->fragment_length, FRAGMENT_LENGTH_LENGTH, "fragment_length");
            klee_assume(byte_to_int(record->RES.fragment->fragment_length, FRAGMENT_LENGTH_LENGTH) != valid_fragment_length);
            local_state = RECORD_RECEIVED;
        }
    }
    else if (!is_record_client_generated && local_state == RECORD_RECEIVED)
    {
        // Failed assertion if we receive a response to an invalid record
        if (record->content_type != Alert_REC)
            kleener_assert("Invalid fragment length");
    }
}

void is_fragment_length_valid_client(RECORD *record, bool is_record_client_generated)
{   
    if (!is_record_client_generated && local_state == INITIAL)
    {
        /* 
        * We only check this requirement for records for which the epoch is zero.
        * This indirectly ensures that the content of the message is not encrypted.
        * Moreover, this requirement only makes sense for handshake messages.
        */ 
        if (record->content_type == Handshake_REC && byte_to_int(record->epoch, EPOCH_LENGTH) == 0)
        {
            // The concrete value is stored as the valid value
            uint16_t valid_fragment_length = byte_to_int(record->RES.fragment->fragment_length, FRAGMENT_LENGTH_LENGTH);

            // Fragment length is made symbolic and assumed to be invalid
            kleener_make_symbolic(record->RES.fragment->fragment_length, FRAGMENT_LENGTH_LENGTH, "fragment_length");
            klee_assume(byte_to_int(record->RES.fragment->fragment_length, FRAGMENT_LENGTH_LENGTH) != valid_fragment_length);
            local_state = RECORD_RECEIVED;
        }
    }
    else if (is_record_client_generated && local_state == RECORD_RECEIVED)
    {
        // Failed assertion if we receive a response to an invalid record
        if (record->content_type != Alert_REC)
            kleener_assert("Invalid fragment length");
    }
}