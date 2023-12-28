#include "klee/Protocols/quic/quic_packets.h"
#include "klee/Protocols/quic/quic_states.h"
#include "klee/Support/Protocols/helper.h"
#include "klee/klee.h"
#include <assert.h>
#include <inttypes.h>

/* Section 5.2.1
* If a client receives a packet that uses a different version than it initially selected, 
* it MUST discard that packet.
*/

/*
A Version Negotiation packet is inherently not version specific. 
* Upon receipt by a client, it will be identified as a Version Negotiation
* packet based on the Version field having a value of 0. (Section 17.2.1)
*/

#define INITIAL 0
#define INITIAL_PACKET_RECEIVED 1
#define RESPONSE_TO_INITIAL_RECEIVED 2


static STATE local_state = INITIAL;
static uint32_t advertised_version = 0;

void are_inconsistent_versions_handled_correctly(Packet *pkt, bool is_packet_client_generated)
{
    uint64_t packet_number = 0;
    if(is_packet_client_generated && local_state == INITIAL && is_header_long(&pkt->base) &&
       decode_packet_type(&pkt->base) == INITIAL_PACKET)
    {
        advertised_version = byte_to_int(pkt->version, 4);
        local_state = INITIAL_PACKET_RECEIVED;
    }
    else if (!is_packet_client_generated && local_state == INITIAL_PACKET_RECEIVED && is_header_long(&pkt->base))
    {
        char symbolic_name[40];
        uint8_t pn_size = decode_packet_number_length(&pkt->base);
        packet_number = byte_to_int(pkt->packet_number, pn_size);
        sprintf(symbolic_name, "%s:%"PRIu64, "version_PN", packet_number);

        kleener_make_symbolic(pkt->version, sizeof(pkt->version), symbolic_name);
        klee_assume(byte_to_int(pkt->version, sizeof(pkt->version)) != advertised_version);
        klee_assume(byte_to_int(pkt->version, sizeof(pkt->version)) != 0x0);
        local_state = RESPONSE_TO_INITIAL_RECEIVED;
    }
    else if (is_packet_client_generated && local_state == RESPONSE_TO_INITIAL_RECEIVED)
    {
        assert(!is_ack_packet_contains_pn(pkt, packet_number));
    }
}

bool inconsistent_versions_enabling_predicate(quic_state state)
{
    return (state.packet_type == INITIAL_PACKET);
}