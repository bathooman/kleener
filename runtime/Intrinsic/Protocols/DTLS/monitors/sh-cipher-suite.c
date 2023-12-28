#include "klee/Protocols/dtls/dtls_monitors.h"
#include "klee/Protocols/dtls/dtls_records.h"
#include "klee/klee.h"
#include <assert.h>

/*
Input-Output Requirement (TLS 1.2 RFC 5246 p. 43)

   cipher_suite
      The single cipher suite selected by the server from the list in
      ClientHello.cipher_suites.

*/

#define INITIAL 0
#define RECORD_RECEIVED 1

static STATE local_state = INITIAL;

static uint8_t *supported_cipher_suites;
static uint64_t supported_cipher_suites_length_int;

void assert_cipher_suite_supported(uint8_t *server_cipher_suite) {
    uint64_t server_cipher_suite_int = byte_to_int(server_cipher_suite, CIPHER_SUITE_LENGTH);
    bool supported = false;
    for (int i=0; i<supported_cipher_suites_length_int; i+=CIPHER_SUITE_LENGTH) {
        supported |= (server_cipher_suite_int == byte_to_int(supported_cipher_suites + i, CIPHER_SUITE_LENGTH));
        if (supported) {
            break;
        }
    }

    if (!supported) {
        assert(0 && "Unsupported cipher suite in SH");
    }
}

/*
 * Monitor fuzzes the (supported) cipher_suites field of the second ClientHello.
 * In the case of a ServerHello response, it checks that the cipher_suite in ServerHello is contained in cipher_suites.
 */

void is_sh_cipher_suite_supported(RECORD *record, bool is_record_client_generated)
{
    if (is_record_client_generated && local_state == INITIAL)
    {
        if (record->content_type == Handshake_REC && record->RES.fragment->handshake_type == Client_Hello_MSG) {
            supported_cipher_suites_length_int = byte_to_int(record->RES.fragment->body.client_hello->cipher_suite_length, CIPHER_SUITE_LENGTH_LENGTH);
            kleener_make_symbolic(record->RES.fragment->body.client_hello->cipher_suites, supported_cipher_suites_length_int, "CH-cipher_suites");
            supported_cipher_suites = malloc(supported_cipher_suites_length_int);
            memcpy(supported_cipher_suites, record->RES.fragment->body.client_hello->cipher_suites, supported_cipher_suites_length_int);
            local_state = RECORD_RECEIVED;
        }
    }
    else if (!is_record_client_generated && local_state == RECORD_RECEIVED)
    {
        if (record->content_type == Handshake_REC && record->RES.fragment->handshake_type == Server_Hello_MSG) {
            assert_cipher_suite_supported(record->RES.fragment->body.server_hello->cipher_suite);
        }
    }
}