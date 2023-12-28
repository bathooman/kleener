#include "klee/Protocols/quic/quic_packets.h"
#include "klee/Protocols/quic/quic_states.h"
#include "klee/Support/Protocols/helper.h"
#include "klee/klee.h"
#include <assert.h>
#include <inttypes.h>

/* Section 17.2
* The byte following the version contains the length in bytes of the 
* Destination Connection ID field that follows it. This length is encoded
* as an 8-bit unsigned integer. In QUIC version 1, this value MUST NOT 
* exceed 20 bytes. Endpoints that receive a version 1 long header with a 
* value larger than 20 MUST drop the packet.
*/

/* Section 19.3
* Receivers send ACK frames (types 0x02 and 0x03) to inform senders of packets 
* they have received and processed. 
*/

#define Version1 0x01

#define INITIAL 0
#define PACKET_RECEIVED 1

static STATE local_state = INITIAL;
static uint64_t packet_number = 0;

void is_dest_id_length_correct_server(Packet *pkt, bool is_packet_client_generated)
{
    if (is_packet_client_generated && local_state == INITIAL && is_header_long(&pkt->base) && byte_to_int(pkt->version, 4) == Version1)
    {
        char symbolic_name[40];
        uint8_t pn_size = decode_packet_number_length(&pkt->base);
        packet_number = byte_to_int(pkt->packet_number, pn_size);
        sprintf(symbolic_name, "%s:%"PRIu64, "destination_id_length_PN", packet_number);

        kleener_make_symbolic(&pkt->destination_id_length, sizeof(pkt->destination_id_length), symbolic_name);
        klee_assume(pkt->destination_id_length > 20);
        local_state = PACKET_RECEIVED;
    }
    else if (!is_packet_client_generated && local_state == PACKET_RECEIVED)
    {
        assert(!is_ack_packet_contains_pn(pkt, packet_number));
    }
}

void is_dest_id_length_correct_client(Packet *pkt, bool is_packet_client_generated)
{
    if (!is_packet_client_generated && local_state == INITIAL && is_header_long(&pkt->base) && byte_to_int(pkt->version, 4) == Version1)
    {
        char symbolic_name[40];
        uint8_t pn_size = decode_packet_number_length(&pkt->base);
        packet_number = byte_to_int(pkt->packet_number, pn_size);
        sprintf(symbolic_name, "%s:%"PRIu64, "destination_id_length_PN", packet_number);

        kleener_make_symbolic(&pkt->destination_id_length, sizeof(pkt->destination_id_length), symbolic_name);
        klee_assume(pkt->destination_id_length > 20);
        local_state = PACKET_RECEIVED;
    }
    else if (is_packet_client_generated && local_state == PACKET_RECEIVED)
    {
        assert(!is_ack_packet_contains_pn(pkt, packet_number));
    }
}

bool dest_id_length_enabling_predicate(quic_state state)
{
    return ((state.packet_type == INITIAL_PACKET) OR
            (state.packet_type == HANDSHAKE_PACKET) OR
            (state.packet_type == RTT0_PACKET));
}