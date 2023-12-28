#ifndef QUIC_STATES
#define QUIC_STATES

#include <stdbool.h>
#include <stdint.h>

#define INIT -1

typedef struct
{
    int8_t packet_type;
    int64_t packet_number;
    int8_t frame_type;
    int8_t frame_index;
}quic_state;


#include "klee/Protocols/quic/quic_packets.h"

void QUIC_server_packet_state_machine(Packet *packet, quic_state *server_current_state);
void QUIC_client_packet_state_machine(Packet *packet, quic_state *client_current_state);
void QUIC_server_frame_state_machine(Frame *frame, quic_state *server_current_state);
void QUIC_client_frame_state_machine(Frame *frame, quic_state *client_current_state);
bool is_state_equal(quic_state current_state, quic_state state_to_check);
void copy_state(quic_state *dest, const quic_state *src);
#endif /* QUIC_STATES */