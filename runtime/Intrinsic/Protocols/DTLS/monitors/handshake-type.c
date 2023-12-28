#include "klee/Protocols/dtls/dtls_monitors.h"
#include "klee/Protocols/dtls/dtls_records.h"
#include "klee/klee.h"
#include <assert.h>

/* Handshake Type Validity Requirement (RFC 5246 Section 7.4 and RFC 6347 Section 4.2.2)

*  The valid values for the handshake type are defined as:
*  enum {
          hello_request(0), client_hello(1), server_hello(2),
          hello_verify_request(3), certificate(11), server_key_exchange (12),
          certificate_request(13), server_hello_done(14),
          certificate_verify(15), client_key_exchange(16),
          finished(20), (255)
        } HandshakeType;
*/

/* Discard Requirement (DTLS 1.2 RFC Section 4.1.2.7):
In general, invalid records SHOULD be silently discarded, 
thus preserving the association; however, an error MAY be 
logged for diagnostic purposes.
*/

/*
* For checking the validity of each type field, We have two choices:
* 1- Making sure that the type is one of the values specified by the RFC.
* 2- Use the concrete value of type in each received record to ensure the validity
* As the latter is stronger than the former, we choose the second option.
* Since we keep track of the protocol interaction and we successfully parsed the 
* received datagram into RECORD data structures, it is safe to assume that the 
* concrete value for each type field in the RECORD structure is valid.
*/


#define INITIAL 0
#define RECORD_RECEIVED 1

static STATE local_state = INITIAL;


void is_handshake_type_valid_server(RECORD *record, bool is_record_client_generated)
{
    // Since only handshake messages have a handshake type, we need to check for it
    if (is_record_client_generated && local_state == INITIAL && record->content_type == Handshake_REC)
    {
        // We only check this requirement for records for which the epoch is zero
        // This indirectly ensures that the content of the message is not encrypted 
        if (byte_to_int(record->epoch , EPOCH_LENGTH) == 0)
        {   
            // We store the valid type
            uint8_t valid_handshake_type = record->RES.fragment->handshake_type;

            // We make the handshake type symbolic and assume it to be invalid
            kleener_make_symbolic(&record->RES.fragment->handshake_type, sizeof(record->RES.fragment->handshake_type), "handshake-type");
            klee_assume(record->RES.fragment->handshake_type != valid_handshake_type);
            local_state = RECORD_RECEIVED;
        }
        
        
    }
    else if (!is_record_client_generated && local_state == RECORD_RECEIVED)
    {
        if (record->content_type != Alert_REC)
            assert(0 && "Invalid handshake type");
    }
}

void is_handshake_type_valid_client(RECORD *record, bool is_record_client_generated)
{
    if (!is_record_client_generated && local_state == INITIAL && record->content_type == Handshake_REC)
    {

        if (byte_to_int(record->epoch , EPOCH_LENGTH) == 0)
        {
            uint8_t valid_handshake_type = record->RES.fragment->handshake_type;
            kleener_make_symbolic(&record->RES.fragment->handshake_type, sizeof(record->RES.fragment->handshake_type), "handshake-type");
            klee_assume(record->RES.fragment->handshake_type != valid_handshake_type);
            local_state = RECORD_RECEIVED;
        }
    }
    else if (is_record_client_generated && local_state == RECORD_RECEIVED)
    {
        if (record->content_type != Alert_REC)
            assert(0 && "Invalid handshake type");
    }
}