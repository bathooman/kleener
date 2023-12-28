#include "klee/Protocols/dtls/dtls_monitors.h"
#include "klee/Protocols/dtls/dtls_records.h"
#include "klee/klee.h"
#include <assert.h>

/* input-output Requirement (DTLS 1.2 RFC 6347 Errata ID: 5186):
In order to avoid sequence number duplication in case of multiple
cookie exchanges, the server MUST use the message_seq in the
ClientHello as the message_seq in its initial HelloVerifyRequest.
*/


/*
DTLS messages are grouped into a series of message flights,
according to the diagrams below (4.2.4):
   Client                                          Server
   ------                                          ------

   ClientHello             -------->                           Flight 1

                           <-------    HelloVerifyRequest      Flight 2

   ClientHello             -------->                           Flight 3

                                              ServerHello    \
                                             Certificate*     \
                                       ServerKeyExchange*      Flight 4
                                      CertificateRequest*     /
                           <--------      ServerHelloDone    /

*/

#define INITIAL 0
#define CH0_RECEIVED 1


static STATE local_state = INITIAL;
static uint8_t ch0_message_sequence[MESSAGE_SEQ_LENGTH];

void is_ch0_hvr_message_sequence_equal(RECORD *record, bool is_record_client_generated)
{
    // Check if a handshake message is received
    if (record->content_type == Handshake_REC)
    {
        // Check if the message is a Client Hello
        if (is_record_client_generated && local_state == INITIAL && record->RES.fragment->handshake_type == Client_Hello_MSG)
        {
            // Check if it is the first Client Hello
            if (record->RES.fragment->body.client_hello->cookie_length == 0)
            {
                // Make the message sequence for the CH0 symbolic and change the state
                kleener_make_symbolic(ch0_message_sequence, sizeof(ch0_message_sequence), "CH0-message-sequence");
                memcpy(record->RES.fragment->message_sequence, ch0_message_sequence, sizeof(record->RES.fragment->message_sequence));                
                local_state = CH0_RECEIVED;
            }
        }
        // Check if the CH0 is received and now HVR is received
        else if (!is_record_client_generated && local_state == CH0_RECEIVED && record->RES.fragment->handshake_type == Hello_Verify_Request_MSG)
        {
            assert(byte_to_int(record->RES.fragment->message_sequence, MESSAGE_SEQ_LENGTH) == byte_to_int(ch0_message_sequence, MESSAGE_SEQ_LENGTH));
        }
    }    
}