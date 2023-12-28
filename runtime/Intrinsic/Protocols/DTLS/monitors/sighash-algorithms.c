#include "klee/Protocols/dtls/dtls_monitors.h"
#include "klee/Protocols/dtls/dtls_records.h"
#include "klee/klee.h"
#include <assert.h>

/* RFC5246#section-7.4.8
The hash and signature algorithms used in the signature MUST be
one of those present in the supported_signature_algorithms field
of the CertificateRequest message.
*/

#define INITIAL 0
#define CER_RECEIVED 1
#define EXIT 2

static STATE local_state = INITIAL;
static uint8_t *signature_hash_algorithms;
static size_t signature_hash_algorithm_size;

bool is_algorithm_in_set(uint8_t *chosen_algorithm, uint8_t *set_of_algorithms, size_t set_size)
{
    for (int i = 0; i < set_size ; i += 2)
    {
        if (memcmp(chosen_algorithm, set_of_algorithms + i, 2) == 0)
        {
            return true;
        }
    }
    return false;
}

void is_hash_sig_algorithm_equal(RECORD *record, bool is_record_client_generated)
{    
    // Check if a handshake message is received
    if (record->content_type == Handshake_REC)
    {
        // Check if the message is a CERTIFICATE REQUEST
        if (!is_record_client_generated && local_state == INITIAL && record->RES.fragment->handshake_type == Certificate_Request_MSG)
        {
            // Make the signature hash symbolic
            signature_hash_algorithm_size = byte_to_int(record->RES.fragment->body.certificate_request->signature_hash_algorithms_length, SIGNATURE_HASH_ALGORITHM_LENGTH);
            signature_hash_algorithms = malloc(signature_hash_algorithm_size);
            kleener_make_symbolic(signature_hash_algorithms, signature_hash_algorithm_size, "sig-hash-algorithm");
            memcpy(record->RES.fragment->body.certificate_request->signature_hash_algorithms, signature_hash_algorithms, signature_hash_algorithm_size);                
            local_state = CER_RECEIVED;
        }
        if (is_record_client_generated && local_state == CER_RECEIVED && record->RES.fragment->handshake_type == Certificate_Verify_MSG)
        {
            uint8_t chosen_signature_algorithm[2];
            memcpy(chosen_signature_algorithm, record->RES.fragment->body.certificate_verify->signature_hash_algorithms, sizeof(chosen_signature_algorithm));
            assert(is_algorithm_in_set(chosen_signature_algorithm, signature_hash_algorithms, signature_hash_algorithm_size));
            local_state = EXIT;
        }
        if (local_state == EXIT)
        {
            return;
        }
    }
}
