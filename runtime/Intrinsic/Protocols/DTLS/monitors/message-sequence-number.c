#include "klee/Protocols/dtls/dtls_monitors.h"
#include "klee/Protocols/dtls/dtls_records.h"
#include "klee/klee.h"
#include <assert.h>

#define CH0_VALID_MESSAGE_SEQUENCE 0 
#define CH2_VALID_MESSAGE_SEQUENCE 1 
#define CKE_VALID_MESSAGE_SEQUENCE 2 
#define HVR_VALID_MESSAGE_SEQUENCE 0 
#define SH_VALID_MESSAGE_SEQUENCE 1
#define SHD_VALID_MESSAGE_SEQUENCE 2

#define INITIAL 0
#define RECORD_RECEIVED 1


static STATE local_state = INITIAL;

static int8_t return_valid_value(const RECORD *record)
{
    if (record->content_type == Handshake_REC)
    {
        switch (record->RES.fragment->handshake_type)
        {
        case Client_Hello_MSG:
            if (record->RES.fragment->body.client_hello->cookie_length == 0)
            {
                return CH0_VALID_MESSAGE_SEQUENCE;
            }
            else
            {
                return CH2_VALID_MESSAGE_SEQUENCE;
            }
            break;
        
        case Client_Key_Exchange_MSG:
            return CKE_VALID_MESSAGE_SEQUENCE;
            break;

        case Hello_Verify_Request_MSG:
            return HVR_VALID_MESSAGE_SEQUENCE;
            break;

        case Server_Hello_MSG:
            return SH_VALID_MESSAGE_SEQUENCE;
            break;

        case Server_Hello_Done_MSG:
            return SHD_VALID_MESSAGE_SEQUENCE;
            break;
        default:
            return -1;
            break;
        }
    }
    return -1;
}

void is_message_sequence_valid_server(RECORD *record, bool is_record_client_generated)
{
    if (is_record_client_generated && local_state == INITIAL)
    {
        // Todo: Check if it is a handshake message
        kleener_make_symbolic(record->RES.fragment->message_sequence, sizeof(record->RES.fragment->message_sequence), "message_sequence");
        int8_t valid_value = return_valid_value(record);
        if (valid_value == -1)
        {
            printf("\nRecord is not supported!\n");
            exit(-1);
        }
                

        klee_assume(byte_to_int(record->RES.fragment->message_sequence, sizeof(record->RES.fragment->message_sequence)) != valid_value);
        local_state = RECORD_RECEIVED;
    }
    else if (!is_record_client_generated && local_state == RECORD_RECEIVED)
    {
        if (record->content_type != Alert_REC)
            assert(0 && "invalid message sequence");
    }
}

void is_message_sequence_valid_client(RECORD *record, bool is_record_client_generated)
{
    if (!is_record_client_generated && local_state == INITIAL)
    {
        // Todo: Check if it is a handshake message
        kleener_make_symbolic(record->RES.fragment->message_sequence, sizeof(record->RES.fragment->message_sequence), "message_sequence");
        int8_t valid_value = return_valid_value(record);
        if (valid_value == -1)
        {
            printf("\nRecord is not supported!\n");
            exit(-1);
        }
        klee_assume(byte_to_int(record->RES.fragment->message_sequence, sizeof(record->RES.fragment->message_sequence)) != valid_value);
        local_state = RECORD_RECEIVED;
    }
    else if (is_record_client_generated && local_state == RECORD_RECEIVED)
    {
        if (record->content_type != Alert_REC)
            assert(0 && "invalid message sequence");
    }
}