#include "klee/Protocols/quic/quic_packets.h"
#include "klee/Protocols/quic/quic_states.h"
#include "klee/Support/Protocols/helper.h"
#include "klee/klee.h"
#include <assert.h>

/*
* If the version selected by the client is not acceptable to the server, 
* the server responds with a Version Negotiation packet; (Section 6.1)
* The Version Negotiation packet is a response to a client packet that 
* contains a version that is not supported by the server. It is only sent
* by servers. (Section 17.2.1)
* A Version Negotiation packet is inherently not version specific. 
* Upon receipt by a client, it will be identified as a Version Negotiation
* packet based on the Version field having a value of 0. (17.2.1)
*/

#define Version1 0x01
#define VersionDraft27 0xff00001b 
#define VersionDraft29 0xff00001d
#define Version_Negotiation 0x0

#define INITIAL 0
#define PACKET_RECEIVED 1

static STATE local_state = INITIAL;

void is_version_negotiation_done_correctly_server(Packet *pkt, bool is_packet_client_generated)
{
    if (is_packet_client_generated && 
        (decode_packet_type(&pkt->base) == INITIAL_PACKET || decode_packet_type(&pkt->base) == HANDSHAKE_PACKET) && 
        local_state == INITIAL)
    {
        kleener_make_symbolic(pkt->version, sizeof(pkt->version), "version");
        klee_assume(!(
                    (byte_to_int(pkt->version, 4) == Version1) OR
                    (byte_to_int(pkt->version, 4) == VersionDraft27) OR
                    (byte_to_int(pkt->version, 4) == VersionDraft29)
                    ));
        
        local_state = PACKET_RECEIVED;
    }
    if (!is_packet_client_generated && local_state == PACKET_RECEIVED)
    {
        assert(byte_to_int(pkt->version, 4) == Version_Negotiation);
    }
}

bool version_negotation_enabling_predicate(quic_state state)
{
    return ((state.packet_type == INITIAL_PACKET) OR 
            (state.packet_type == HANDSHAKE_PACKET));
}