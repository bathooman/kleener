#include "klee/Protocols/quic/quic_packets.h"
#include "klee/Protocols/quic/quic_states.h"
#include "klee/Support/Protocols/helper.h"
#include "klee/klee.h"
#include <assert.h>

#define INITIAL 0
#define PACKET_RECEIVED 1

static STATE local_state = INITIAL;

void is_crypto_length_correct_server(Packet *pkt, bool is_packet_client_generated)
{
    uint64_t packet_number = 0;
    if (is_packet_client_generated && local_state == INITIAL)
    {
        Frame *frame = pkt->enabled_frame;
        
    }
    else if (!is_packet_client_generated && local_state == PACKET_RECEIVED)
    {      
        assert(!is_ack_packet_contains_pn(pkt, packet_number));
    }
}

void is_crypto_length_correct_client(Packet *pkt, bool is_packet_client_generated)
{
    uint64_t packet_number = 0;
    if (!is_packet_client_generated && local_state == INITIAL)
    {
        Frame *frame = pkt->enabled_frame;
        
    }
    else if (is_packet_client_generated && local_state == PACKET_RECEIVED)
    {      
        assert(!is_ack_packet_contains_pn(pkt, packet_number));
    }
}

bool crypto_length_enabling_predicate(quic_state state)
{
    return (state.frame_type == CRYPTO_FRAME);
}