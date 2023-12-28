#include "klee/Protocols/dtls/dtls_monitors.h"
#include "klee/Protocols/dtls/dtls_records.h"
#include "klee/klee.h"
#include <assert.h>


#define INITIAL 0
#define CER_RECEIVED 1

static STATE local_state = INITIAL;

void is_hash_sig_algorithm_length_valid(RECORD *record, bool is_record_client_generated)
{    
    // Check if a handshake message is received
    if (record->content_type == Handshake_REC)
    {
        // Check if the message is a CERTIFICATE REQUEST
        if (!is_record_client_generated && local_state == INITIAL && record->RES.fragment->handshake_type == Certificate_Request_MSG)
        {
            uint8_t valid_signature_hash_algorithms_length[SIGNATURE_HASH_LENGTH_LENGTH];
            memcpy(valid_signature_hash_algorithms_length, record->RES.fragment->body.certificate_request->signature_hash_algorithms_length, SIGNATURE_HASH_LENGTH_LENGTH);
            kleener_make_symbolic(record->RES.fragment->body.certificate_request->signature_hash_algorithms_length, SIGNATURE_HASH_LENGTH_LENGTH, "sig_length");
            klee_assume(byte_to_int(record->RES.fragment->body.certificate_request->signature_hash_algorithms_length, SIGNATURE_HASH_LENGTH_LENGTH) != byte_to_int(valid_signature_hash_algorithms_length, SIGNATURE_HASH_LENGTH_LENGTH));
            local_state = CER_RECEIVED;
        }
        else if (is_record_client_generated && local_state == CER_RECEIVED && record->content_type != Alert_REC)
        {
            assert(0);
        }
    }
}