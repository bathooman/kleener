#include "klee/Protocols/dtls/dtls_monitors.h"
#include "klee/Protocols/dtls/dtls_records.h"
#include "klee/klee.h"
#include <assert.h>


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

void is_session_id_length_valid_server(RECORD *record, bool is_record_client_generated)
{
    if (is_record_client_generated && local_state == INITIAL)
    {
        /* 
        * We only check this requirement for records for which the epoch is zero.
        * This indirectly ensures that the content of the message is not encrypted. 
        * Moreover, this requirement only makes sense for handshake messages.
        * Lastly, this requirement only makes sense for CH0 and CH2.
        */
        if (byte_to_int(record->epoch, EPOCH_LENGTH) == 0 && record->content_type == Handshake_REC &&
            record->RES.fragment->handshake_type == Client_Hello_MSG)
        {
            // We store the valid value for session id length
            uint8_t valid_session_id_length = record->RES.fragment->body.client_hello->session_id_length;
            
            // We make the session id symbolic and assume it to be invalid
            kleener_make_symbolic(&record->RES.fragment->body.client_hello->session_id_length, SESSION_ID_LENGTH_LENGTH, "session_id_length");
            klee_assume(record->RES.fragment->body.client_hello->session_id_length != valid_session_id_length);
            local_state = RECORD_RECEIVED;
        }
        
    }
    else if (!is_record_client_generated && local_state == RECORD_RECEIVED)
    {
        // The assertion is failed if one side generates a response other than an alert to an invalid input 
        if (record->content_type != Alert_REC)
            kleener_assert("invalid session id length");
    }
}

void is_session_id_length_valid_client(RECORD *record, bool is_record_client_generated)
{
    if (!is_record_client_generated && local_state == INITIAL)
    {
        if (byte_to_int(record->epoch, EPOCH_LENGTH) == 0 && record->content_type == Handshake_REC &&
            record->RES.fragment->handshake_type == Server_Hello_MSG)
        {
            uint8_t valid_session_id_length = record->RES.fragment->body.server_hello->session_id_length;
            
            kleener_make_symbolic(&record->RES.fragment->body.server_hello->session_id_length, SESSION_ID_LENGTH_LENGTH, "session_id_length");
            klee_assume(record->RES.fragment->body.server_hello->session_id_length != valid_session_id_length);
            local_state = RECORD_RECEIVED;
        }
    }
    else if (is_record_client_generated && local_state == RECORD_RECEIVED)
    {
        if (record->content_type != Alert_REC)
            kleener_assert("invalid session id length");
    }
}