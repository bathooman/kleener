#include "klee/Protocols/quic/quic_packets.h"
#include "klee/Protocols/quic/quic_states.h"
#include "klee/Support/Protocols/helper.h"
#include "klee/klee.h"
#include <assert.h>

#define INITIAL 0
#define PACKET_RECEIVED 1

static STATE local_state = INITIAL;

void is_new_token_length_correct_server(Packet *pkt, bool is_packet_client_generated)
{
    uint64_t packet_number = 0;
    if (is_packet_client_generated && local_state == INITIAL)
    {
        Frame *frame = pkt->enabled_frame;
        if (frame->frame_type == NEW_TOKEN_FRAME)
        {
            uint8_t pn_size = decode_packet_number_length(&pkt->base);
            packet_number = byte_to_int(pkt->packet_number, pn_size);

            uint8_t token_length_length = decode_variable_length(frame->body->new_token->token_length);
            uint64_t concrete_packet_length = encoded_length_to_int(frame->body->new_token->token_length, token_length_length);

            kleener_make_symbolic(frame->body->new_token->token_length, token_length_length, "Token_length");
            klee_assume(encoded_length_to_int(frame->body->new_token->token_length, token_length_length) != concrete_packet_length);
            local_state = PACKET_RECEIVED;
        }       
    }
    else if (!is_packet_client_generated && local_state == PACKET_RECEIVED)
    {      
        assert(!is_ack_packet_contains_pn(pkt, packet_number));
    }
}

void is_new_token_length_correct_client(Packet *pkt, bool is_packet_client_generated)
{
    uint64_t packet_number = 0;
    if (!is_packet_client_generated && local_state == INITIAL)
    {
        Frame *frame = pkt->enabled_frame;
        if (frame->frame_type == NEW_TOKEN_FRAME)
        {
            uint8_t pn_size = decode_packet_number_length(&pkt->base);
            packet_number = byte_to_int(pkt->packet_number, pn_size);

            uint8_t token_length_length = decode_variable_length(frame->body->new_token->token_length);
            uint64_t concrete_packet_length = encoded_length_to_int(frame->body->new_token->token_length, token_length_length);

            kleener_make_symbolic(frame->body->new_token->token_length, token_length_length, "Token_length");
            klee_assume(encoded_length_to_int(frame->body->new_token->token_length, token_length_length) != concrete_packet_length);
            local_state = PACKET_RECEIVED;

        }
    }
    else if (is_packet_client_generated && local_state == PACKET_RECEIVED)
    {      
        assert(!is_ack_packet_contains_pn(pkt, packet_number));
    }
}

bool new_token_length_enabling_predicate(quic_state state)
{
    return (state.frame_type == NEW_TOKEN_FRAME);
}