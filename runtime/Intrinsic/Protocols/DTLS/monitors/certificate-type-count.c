#include "klee/Protocols/dtls/dtls_monitors.h"
#include "klee/Protocols/dtls/dtls_records.h"
#include "klee/klee.h"
#include <assert.h>


#define INITIAL 0
#define CER_RECEIVED 1

static STATE local_state = INITIAL;


void is_certificate_type_count_valid(RECORD *record, bool is_record_client_generated)
{    
    // Check if a handshake message is received
    if (record->content_type == Handshake_REC)
    {
        // Check if the message is a CERTIFICATE REQUEST
        if (!is_record_client_generated && local_state == INITIAL && record->RES.fragment->handshake_type == Certificate_Request_MSG)
        {
            uint8_t valid_certificate_types_count = record->RES.fragment->body.certificate_request->certificate_types_count;
            kleener_make_symbolic(&record->RES.fragment->body.certificate_request->certificate_types_count, 1, "count");
            klee_assume(valid_certificate_types_count != record->RES.fragment->body.certificate_request->certificate_types_count);
            local_state = CER_RECEIVED;
        }
        else if (is_record_client_generated && local_state == CER_RECEIVED && record->content_type != Alert_REC)
        {
            assert(0);
        }
    }
}