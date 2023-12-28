#include "klee/Protocols/quic/quic_packets.h"
#include "klee/Protocols/quic/quic_states.h"
#include "klee/Support/Protocols/helper.h"
#include "klee/klee.h"
#include <assert.h>

/* Section 19.7
* The token MUST NOT be empty. A client MUST treat receipt of a NEW_TOKEN frame
* with an empty Token field as a connection error of type FRAME_ENCODING_ERROR.
*/

#define INITIAL 0
#define PACKET_RECEIVED 1

static STATE local_state = INITIAL;

void is_empty_token_handled_correctly_client(Packet *pkt, bool is_packet_client_generated)
{
    if (!is_packet_client_generated && local_state == INITIAL)
    {
        Frame *frame = pkt->enabled_frame;
        if (frame->frame_type == NEW_TOKEN_FRAME)
        {
            uint8_t token_length_length = decode_variable_length(frame->body->new_token->token_length);
            uint8_t *concrete_token_length = malloc(token_length_length);
            memcpy(concrete_token_length, frame->body->new_token->token_length, token_length_length);
            kleener_make_symbolic(frame->body->new_token->token_length, token_length_length, "new_token_length");
            klee_assume((frame->body->new_token->token_length[0] & 0b11000000) == (concrete_token_length[0] & 0b11000000));
            klee_assume((frame->body->new_token->token_length[0] & 0b00111111) == 0x0);
            for (int i = 1 ; i < token_length_length ; i++)
            {
                klee_assume((frame->body->new_token->token_length[i] == 0x0));
            }          
            local_state = PACKET_RECEIVED;   
        }        
    }
    else if (is_packet_client_generated && local_state == PACKET_RECEIVED)
    {
        assert(is_returned_error_code_correct(pkt, FRAME_ENCODING_ERROR));
    }

}

bool empty_token_enabling_predicate(quic_state state)
{
    return (state.frame_type == NEW_TOKEN_FRAME);
}