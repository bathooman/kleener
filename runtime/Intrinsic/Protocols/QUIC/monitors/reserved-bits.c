#include "klee/Protocols/quic/quic_packets.h"
#include "klee/Protocols/quic/quic_states.h"
#include "klee/Support/Protocols/helper.h"
#include "klee/klee.h"
#include <assert.h>

/* Section 17.2
* Two bits (those with a mask of 0x0c) of byte 0 are reserved across multiple packet types. 
* These bits are protected using header protection. The value included prior to protection 
* MUST be set to 0. An endpoint MUST treat receipt of a packet that has a non-zero value for 
* these bits after removing both packet and header protection as a connection error of type 
* PROTOCOL_VIOLATION.
*/

#define INITIAL 0
#define PACKET_RECEIVED 1

static STATE local_state = INITIAL;

void are_reserved_bits_correct_server(Packet *pkt, bool is_packet_client_generated)
{
    if (is_packet_client_generated && local_state == INITIAL)
    {
        uint8_t base_byte_concrete_value = pkt->base;
        kleener_make_symbolic(&pkt->base, sizeof(pkt->base), "reserved_bits");
        klee_assume((pkt->base & 0b11110011) == (base_byte_concrete_value & 0b11110011));
        klee_assume((pkt->base & 0b00001100) != (base_byte_concrete_value & 0b00001100));

        local_state = PACKET_RECEIVED;
    }
    else if (!is_packet_client_generated && local_state == PACKET_RECEIVED)
    {
        assert(is_returned_error_code_correct(pkt, PROTOCOL_VIOLATION));
    }
}

void are_reserved_bits_correct_client(Packet *pkt, bool is_packet_client_generated)
{
    if (!is_packet_client_generated && local_state == INITIAL)
    {
        uint8_t base_byte_concrete_value = pkt->base;
        kleener_make_symbolic(&pkt->base, sizeof(pkt->base), "reserved_bits");
        klee_assume((pkt->base & 0b11110011) == (base_byte_concrete_value & 0b11110011));
        klee_assume((pkt->base & 0b00001100) != (base_byte_concrete_value & 0b00001100));

        local_state = PACKET_RECEIVED;
    }
    else if (is_packet_client_generated && local_state == PACKET_RECEIVED)
    {
        assert(is_returned_error_code_correct(pkt, PROTOCOL_VIOLATION));
    }
}   

bool reserved_bits_enabling_predicate(quic_state state)
{
    return 1;
}