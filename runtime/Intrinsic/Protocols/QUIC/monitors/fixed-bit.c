#include "klee/Protocols/quic/quic_packets.h"
#include "klee/Protocols/quic/quic_states.h"
#include "klee/Support/Protocols/helper.h"
#include "klee/klee.h"
#include <assert.h>
#include <inttypes.h>

/* Section 17.2
* The next bit (0x40) of byte 0 is set to 1, unless the packet is a 
* Version Negotiation packet. Packets containing a zero value for this bit
* are not valid packets in this version and MUST be discarded. 
*/

/* Section 19.3
* Receivers send ACK frames (types 0x02 and 0x03) to inform senders of packets 
* they have received and processed. 
*/
#define Version_Negotiation 0x0

#define INITIAL 0
#define PACKET_RECEIVED 1


static STATE local_state = INITIAL;

void is_fixed_bit_correct_server(Packet *pkt, bool is_packet_client_generated)
{
    uint64_t packet_number = 0;
    if (is_packet_client_generated && local_state == INITIAL)
    {
        if (!is_header_long(&pkt->base) || (is_header_long(&pkt->base) && (byte_to_int(pkt->version, 4) != Version_Negotiation)))
        {
            char symbolic_name[20];
            uint8_t base_byte_concrete_value = pkt->base;
            uint8_t pn_size = decode_packet_number_length(&pkt->base);
            packet_number = byte_to_int(pkt->packet_number, pn_size);
            sprintf(symbolic_name, "%s:%"PRIu64, "fixed_bit_PN", packet_number);

            kleener_make_symbolic(&pkt->base, sizeof(pkt->base), symbolic_name);
            klee_assume((pkt->base & 0b10111111) == (base_byte_concrete_value & 0b10111111));
            klee_assume((pkt->base & 0b01000000) != (base_byte_concrete_value & 0b01000000));

            local_state = PACKET_RECEIVED;
        }        
    }
    else if (!is_packet_client_generated && local_state == PACKET_RECEIVED)
    {      
        assert(!is_ack_packet_contains_pn(pkt, packet_number));
    }
}

void is_fixed_bit_correct_client(Packet *pkt, bool is_packet_client_generated)
{
    uint64_t packet_number = 0;
    if (!is_packet_client_generated && local_state == INITIAL)
    {
        if (!is_header_long(&pkt->base) || (is_header_long(&pkt->base) && (byte_to_int(pkt->version, 4) != Version_Negotiation)))
        {
            char symbolic_name[20];
            uint8_t base_byte_concrete_value = pkt->base;
            uint8_t pn_size = decode_packet_number_length(&pkt->base);
            packet_number = byte_to_int(pkt->packet_number, pn_size);
            sprintf(symbolic_name, "%s:%"PRIu64, "fixed_bit_PN", packet_number);

            kleener_make_symbolic(&pkt->base, sizeof(pkt->base), symbolic_name);
            klee_assume((pkt->base & 0b10111111) == (base_byte_concrete_value & 0b10111111));
            klee_assume((pkt->base & 0b01000000) != (base_byte_concrete_value & 0b01000000));

            local_state = PACKET_RECEIVED;
        }        
    }
    else if (is_packet_client_generated && local_state == PACKET_RECEIVED)
    {      
        assert(!is_ack_packet_contains_pn(pkt, packet_number));
    }
}

bool fixed_bit_enabling_predicate(quic_state state)
{
    return 1;
}