#include "klee/Protocols/dtls/dtls_monitors.h"
#include "klee/Protocols/dtls/dtls_records.h"
#include "klee/klee.h"
#include <assert.h>

#define INITIAL 0
#define RECORD_RECEIVED 1

static STATE local_state = INITIAL;

void is_extensions_length_valid_server(RECORD *record, bool is_record_client_generated)
{
    if (is_record_client_generated && record->content_type == Handshake_REC && record->RES.fragment->handshake_type == Client_Hello_MSG)
    {
        if (record->RES.fragment->body.client_hello->extensions != NULL)
        {
            uint16_t valid_extensions_length = byte_to_int(record->RES.fragment->body.client_hello->extension_length,
                                                           sizeof(record->RES.fragment->body.client_hello->extension_length));

            kleener_make_symbolic(record->RES.fragment->body.client_hello->extension_length, 
                                  sizeof(record->RES.fragment->body.client_hello->extension_length),
                                  "Extension-length");
                                  
            klee_assume(
                byte_to_int(record->RES.fragment->body.client_hello->extension_length,
                                                           sizeof(record->RES.fragment->body.client_hello->extension_length))
                !=
                valid_extensions_length
            );
            local_state = RECORD_RECEIVED;
        }
    }
    else if (!is_record_client_generated && local_state == RECORD_RECEIVED)
    {
        if (record->content_type != Alert_REC)
            assert(0 && "Invalid Extensions length");
    }
}

void is_extensions_length_valid_client(RECORD *record, bool is_record_client_generated)
{
    if (!is_record_client_generated && record->content_type == Handshake_REC && record->RES.fragment->handshake_type == Server_Hello_MSG)
    {
        if (record->RES.fragment->body.server_hello->extensions != NULL)
        {
            uint16_t valid_extensions_length = byte_to_int(record->RES.fragment->body.server_hello->extension_length,
                                                           sizeof(record->RES.fragment->body.server_hello->extension_length));

            kleener_make_symbolic(record->RES.fragment->body.server_hello->extension_length, 
                                  sizeof(record->RES.fragment->body.server_hello->extension_length),
                                  "Extension-length");
                                  
            klee_assume(
                byte_to_int(record->RES.fragment->body.server_hello->extension_length,
                                                           sizeof(record->RES.fragment->body.server_hello->extension_length))
                !=
                valid_extensions_length
            );
            local_state = RECORD_RECEIVED;
        }
    }
    else if (is_record_client_generated && local_state == RECORD_RECEIVED)
    {
        if (record->content_type != Alert_REC)
            assert(0 && "Invalid Extensions length");
    }
}