#include "klee/Protocols/dtls/dtls_monitors.h"
#include "klee/Protocols/dtls/dtls_records.h"
#include "klee/klee.h"
#include <assert.h>

/* Requirement (DTLS 1.2 RFC Section 4.1)
* Identical to the length field in a TLS 1.2 record
*/

/* Requirement (TLS 1.2 RFC Section 6.2.1)
* The length (in bytes) of the following TLSPlaintext.fragment
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

void is_record_length_valid_server(RECORD *record, bool is_record_client_generated)
{
    if (is_record_client_generated && local_state == INITIAL)
    {
        // We only check this requirement for records for which the epoch is zero
        // This indirectly ensures that the content of the message is not encrypted 
        if(byte_to_int(record->epoch, sizeof(record->epoch)) == 0)
        {
            // The concrete value is stored as the valid value
            uint16_t valid_record_length = byte_to_int(record->record_length, RECORD_LENGTH_LENGTH);

            // The record length is made symbolic and assumed to be invalid
            kleener_make_symbolic(record->record_length, sizeof(record->record_length), "record_length");
            klee_assume(byte_to_int(record->record_length, RECORD_LENGTH_LENGTH) != valid_record_length);
        }                
    }
    else if (!is_record_client_generated && local_state == RECORD_RECEIVED)
    {
        // The assertion is failed if one side generates a response other than an alert to an invalid input 
        if (record->content_type != Alert_REC)
            assert(0 && "Invalid record length");
    }
}

void is_record_length_valid_client(RECORD *record, bool is_record_client_generated)
{
    if (!is_record_client_generated && local_state == INITIAL)
    {
        if(byte_to_int(record->epoch, sizeof(record->epoch)) == 0)
        {
            uint16_t valid_record_length = byte_to_int(record->record_length, RECORD_LENGTH_LENGTH);

            kleener_make_symbolic(record->record_length, sizeof(record->record_length), "record_length");
            klee_assume(byte_to_int(record->record_length, RECORD_LENGTH_LENGTH) != valid_record_length);
        }        
    }
    else if (is_record_client_generated && local_state == RECORD_RECEIVED)
    {
        if (record->content_type != Alert_REC)
            assert(0 && "Invalid record length");
    }
}