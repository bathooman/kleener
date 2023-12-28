#include "klee/Protocols/quic/quic_packets.h"
#include "klee/Protocols/quic/quic_states.h"
#include "klee/Support/Protocols/helper.h"
#include "klee/klee.h"
#include <assert.h>

/*
* Section 17.2.2
* Initial packets sent by the server MUST set the Token Length field to 0; 
* clients that receive an Initial packet with a non-zero Token Length field MUST 
* either discard the packet or generate a connection error of type PROTOCOL_VIOLATION.
*/

#define INITIAL 0
#define PACKET_RECEIVED 1


static STATE local_state = INITIAL;

#define Valid_Initial_Token_length 0b0

void is_initial_token_length_valid_client(Packet *pkt, bool is_packet_client_generated)
{
    if (!is_packet_client_generated && decode_packet_type(&pkt->base) == INITIAL_PACKET && local_state == INITIAL)
    {
        uint8_t token_length_concrete_value = pkt->token_length;
        kleener_make_symbolic(&pkt->token_length, sizeof(pkt->token_length), "token_length");
        klee_assume((pkt->token_length & 0b11000000) == (token_length_concrete_value & 0b11000000));
        klee_assume((pkt->token_length & 0b00111111) != (token_length_concrete_value & 0b00111111));
        local_state = PACKET_RECEIVED;
    }
    else if (is_packet_client_generated && local_state == PACKET_RECEIVED)
    {        
        assert(is_returned_error_code_correct(pkt, PROTOCOL_VIOLATION));
    }
}

bool initial_token_length_enabling_predicate(quic_state state)
{
    return (state.packet_type == INITIAL_PACKET);
}

