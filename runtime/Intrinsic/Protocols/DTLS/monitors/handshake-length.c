#include "klee/Protocols/dtls/dtls_monitors.h"
#include "klee/Protocols/dtls/dtls_records.h"
#include "klee/klee.h"
#include <assert.h>

/* TLS 1.2 RFC Section 7.4
* length : number of bytes in a message
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

void is_handshake_length_valid_server(RECORD *record, bool is_record_client_generated)
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
            uint16_t valid_handshake_length = byte_to_int(record->RES.fragment->handshake_length, HANDSHAKE_LENGTH_LENGTH);

            // Handshake length is made symbolic and assumed to be invalid
            kleener_make_symbolic(record->RES.fragment->handshake_length, HANDSHAKE_LENGTH_LENGTH, "handshake_length");
            klee_assume(byte_to_int(record->RES.fragment->handshake_length, HANDSHAKE_LENGTH_LENGTH) != valid_handshake_length);
            local_state = RECORD_RECEIVED;
        }
    }
    else if (!is_record_client_generated && local_state == RECORD_RECEIVED)
    {
        // Failed assertion if we receive a response to an invalid record
        if (record->content_type != Alert_REC)
            kleener_assert("Invalid handshake length");
    }
}

void is_handshake_length_valid_client(RECORD *record, bool is_record_client_generated)
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
            uint16_t valid_handshake_length = byte_to_int(record->RES.fragment->handshake_length, HANDSHAKE_LENGTH_LENGTH);

            // Handshake length is made symbolic and assumed to be invalid
            kleener_make_symbolic(record->RES.fragment->handshake_length, HANDSHAKE_LENGTH_LENGTH, "handshake_length");
            klee_assume(byte_to_int(record->RES.fragment->handshake_length, HANDSHAKE_LENGTH_LENGTH) != valid_handshake_length);
            local_state = RECORD_RECEIVED;
        }
    }
    else if (is_record_client_generated && local_state == RECORD_RECEIVED)
    {
        // Failed assertion if we receive a response to an invalid record
        if (record->content_type != Alert_REC)
            kleener_assert("Invalid handshake length");
    }
}