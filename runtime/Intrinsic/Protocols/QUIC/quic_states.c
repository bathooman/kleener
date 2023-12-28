#include "klee/Protocols/quic/quic_packets.h"
#include "klee/Protocols/quic/quic_states.h"
#include "klee/Support/Protocols/helper.h"
#include <stdint.h>
#include <stdio.h>
#include <memory.h>
#include <errno.h>
#include <stdlib.h>
#include <assert.h>
#include <klee/klee.h>
#include <stdbool.h>

void QUIC_server_packet_state_machine(Packet *packet, quic_state *server_current_state)
{
    
    uint8_t pn_size = decode_packet_number_length(&packet->base);

    if (is_header_long(&packet->base))
    {
        switch (decode_packet_type(&packet->base))
        {
        case INITIAL_PACKET:            
            server_current_state->packet_type = INITIAL_PACKET;
            server_current_state->packet_number = byte_to_int(packet->packet_number, pn_size);
            printf("[++] INITIAL is recieved by the server. PN:%lld\n", server_current_state->packet_number);
            break;
        
        case RTT0_PACKET:
            server_current_state->packet_type = RTT0_PACKET;
            server_current_state->packet_number = byte_to_int(packet->packet_number, pn_size);
            printf("[++] 0-RTT is recieved by the server. PN:%lld\n", server_current_state->packet_number);
            break;

        case HANDSHAKE_PACKET:
            server_current_state->packet_type = HANDSHAKE_PACKET;
            server_current_state->packet_number = byte_to_int(packet->packet_number, pn_size);
            printf("[++] HANDSHAKE is recieved by the server. PN:%lld\n", server_current_state->packet_number);
            break;

        default:
            printf("Unknown Packet type:%X\n", packet->base);
            break;
        }
    }
    else
    {
        // If the packet does not have long header, it is a 1-RTT packet        
        server_current_state->packet_type = RTT1_PACKET;
        server_current_state->packet_number = byte_to_int(packet->packet_number, pn_size);
        printf("[++] 1-RTT is recieved by the server. PN:%lld\n", server_current_state->packet_number);
    }
    
}

void QUIC_client_packet_state_machine(Packet *packet, quic_state *client_current_state)
{
    uint8_t pn_size = decode_packet_number_length(&packet->base);

    if (is_header_long(&packet->base))
    {
        if (byte_to_int(packet->version, 4) == 0)
        {
            // Version Negotiation packets will not change the state
            printf("[++] Version Negotiation is recieved by the client.\n");
            return;
        }
        switch (decode_packet_type(&packet->base))
        {
        case INITIAL_PACKET:            
            client_current_state->packet_type = INITIAL_PACKET;
            client_current_state->packet_number = byte_to_int(packet->packet_number, pn_size);
            printf("[++] INITIAL is recieved by the client. PN:%lld\n", client_current_state->packet_number);
            break;
        
        case RTT0_PACKET:
            client_current_state->packet_type = RTT0_PACKET;
            client_current_state->packet_number = byte_to_int(packet->packet_number, pn_size);
            printf("[++] 0-RTT is recieved by the client. PN:%lld\n", client_current_state->packet_number);
            break;

        case HANDSHAKE_PACKET:
            client_current_state->packet_type = HANDSHAKE_PACKET;
            client_current_state->packet_number = byte_to_int(packet->packet_number, pn_size);
            printf("[++] HANDSHAKE is recieved by the client. PN:%lld\n", client_current_state->packet_number);
            break;

        default:
            printf("Unknown Packet type:%X\n", packet->base);
            break;
        }
    }
    else
    {
        // If the packet does not have long header, it is a 1-RTT packet        
        client_current_state->packet_type = RTT1_PACKET;
        client_current_state->packet_number = byte_to_int(packet->packet_number, pn_size);
        printf("[++] 1-RTT is recieved by the client. PN:%lld\n", client_current_state->packet_number);
    }
    
}

void QUIC_server_frame_state_machine(Frame *frame, quic_state *server_current_state)
{
    switch (frame->frame_type) 
    {
    case STOP_SENDING_FRAME:
        server_current_state->frame_type = STOP_SENDING_FRAME;
        server_current_state->frame_index = frame->frame_index;
        printf("[+++] Stop_Sending is recieved by the server. index:%d\n", server_current_state->frame_index);
        break;

    case PADDING_FRAME:
        server_current_state->frame_type = PADDING_FRAME;
        server_current_state->frame_index = frame->frame_index;
        printf("[+++] Padding is recieved by the server. index:%d\n", server_current_state->frame_index);
        break;
    
    case PING_FRAME:
        server_current_state->frame_type = PING_FRAME;
        server_current_state->frame_index = frame->frame_index;
        printf("[+++] Ping is recieved by the server. index:%d\n", server_current_state->frame_index);
        break;

    case ACK_FRAME_START ... ACK_FRAME_END :
        server_current_state->frame_type = frame->frame_type;
        server_current_state->frame_index = frame->frame_index;
        printf("[+++] ACK is recieved by the server. index:%d\n", server_current_state->frame_index);
        break;
    case CRYPTO_FRAME:
        server_current_state->frame_type = CRYPTO_FRAME;
        server_current_state->frame_index = frame->frame_index;
        printf("[+++] Crypto is recieved by the server. index:%d\n", server_current_state->frame_index);
        break;
    case NEW_TOKEN_FRAME:
        server_current_state->frame_type = NEW_TOKEN_FRAME;
        server_current_state->frame_index = frame->frame_index;
        printf("[+++] NT is recieved by the server. index:%d\n", server_current_state->frame_index);
        break;
    case STREAM_FRAME_START ... STREAM_FRAME_END:
        server_current_state->frame_type = frame->frame_type;
        server_current_state->frame_index = frame->frame_index;
        printf("[+++] Stream is recieved by the server. index:%d\n", server_current_state->frame_index);
        break;
    case NEW_CONID_FRAME:
        server_current_state->frame_type = NEW_CONID_FRAME;
        server_current_state->frame_index = frame->frame_index;
        printf("[+++] NCI is recieved by the server. index:%d\n", server_current_state->frame_index);
        break;
    case HANDSHAKE_DONE_FRAME:
        server_current_state->frame_type = HANDSHAKE_DONE_FRAME;
        server_current_state->frame_index = frame->frame_index;
        printf("[+++] Done is recieved by the server. index:%d\n", server_current_state->frame_index);
        break;

    case CONNECTION_CLOSE_START ... CONNECTION_CLOSE_END:
        server_current_state->frame_type = frame->frame_type;
        server_current_state->frame_index = frame->frame_index;
        printf("[+++] CONNECTION CLOSE is recieved by the server. index:%d.\n", server_current_state->frame_index);
        break;
    
    case ACK_FREQUENCY_FRAME:
        server_current_state->frame_type = ACK_FREQUENCY_FRAME;
        server_current_state->frame_index = frame->frame_index;
        printf("[+++] ACK Frequency is recieved by the server. index:%d\n", server_current_state->frame_index);
        break;

    case PATH_CHALLENGE_FRAME:
        server_current_state->frame_type = PATH_CHALLENGE_FRAME;
        server_current_state->frame_index = frame->frame_index;
        printf("[+++] PATH CHALLENGE is recieved by the server. index:%d\n", server_current_state->frame_index);
        break;

    case PATH_RESPONSE_FRAME:
        server_current_state->frame_type = PATH_RESPONSE_FRAME;
        server_current_state->frame_index = frame->frame_index;
        printf("[+++] PATH Response is recieved by the server. index:%d\n", server_current_state->frame_index);
        break;
    }
}

void QUIC_client_frame_state_machine(Frame *frame, quic_state *client_current_state)
{
    switch (frame->frame_type) 
    {
    case STOP_SENDING_FRAME:
        client_current_state->frame_type = STOP_SENDING_FRAME;
        client_current_state->frame_index = frame->frame_index;
        printf("[+++] Stop_Sending is recieved by the client. index:%d\n", client_current_state->frame_index);
        break;

    case PADDING_FRAME:
        client_current_state->frame_type = PADDING_FRAME;
        client_current_state->frame_index = frame->frame_index;
        printf("[+++] Padding is recieved by the client. index:%d\n", client_current_state->frame_index);
        break;

    case PING_FRAME:
        client_current_state->frame_type = PING_FRAME;
        client_current_state->frame_index = frame->frame_index;
        printf("[+++] Ping is recieved by the client. index:%d\n", client_current_state->frame_index);
        break;

    case ACK_FRAME_START ... ACK_FRAME_END :
        client_current_state->frame_type = frame->frame_type;
        client_current_state->frame_index = frame->frame_index;
        printf("[+++] ACK is recieved by the client. index:%d\n", client_current_state->frame_index);
        break;
    case CRYPTO_FRAME:
        client_current_state->frame_type = CRYPTO_FRAME;
        client_current_state->frame_index = frame->frame_index;
        printf("[+++] Crypto is recieved by the client. index:%d\n", client_current_state->frame_index);
        break;
    case NEW_TOKEN_FRAME:
        client_current_state->frame_type = NEW_TOKEN_FRAME;
        client_current_state->frame_index = frame->frame_index;
        printf("[+++] NT is recieved by the client. index:%d\n", client_current_state->frame_index);
        break;
    case STREAM_FRAME_START ... STREAM_FRAME_END:
        client_current_state->frame_type = frame->frame_type;
        client_current_state->frame_index = frame->frame_index;
        printf("[+++] Stream is recieved by the client. index:%d\n", client_current_state->frame_index);
        break;
    case NEW_CONID_FRAME:
        client_current_state->frame_type = NEW_CONID_FRAME;
        client_current_state->frame_index = frame->frame_index;
        printf("[+++] NCI is recieved by the client. index:%d\n", client_current_state->frame_index);
        break;
    case HANDSHAKE_DONE_FRAME:
        client_current_state->frame_type = HANDSHAKE_DONE_FRAME;
        client_current_state->frame_index = frame->frame_index;
        printf("[+++] Done is recieved by the client. index:%d\n", client_current_state->frame_index);
        break;
    
    case CONNECTION_CLOSE_START ... CONNECTION_CLOSE_END:
        client_current_state->frame_type = frame->frame_type;
        client_current_state->frame_index = frame->frame_index;
        printf("[+++] CONNECTION CLOSE is recieved by the client. index:%d\n", client_current_state->frame_index);
        break;
    
    case ACK_FREQUENCY_FRAME:
        client_current_state->frame_type = ACK_FREQUENCY_FRAME;
        client_current_state->frame_index = frame->frame_index;
        printf("[+++] ACK Frequency is recieved by the client. index:%d\n", client_current_state->frame_index);
        break;

    case PATH_CHALLENGE_FRAME:
        client_current_state->frame_type = PATH_CHALLENGE_FRAME;
        client_current_state->frame_index = frame->frame_index;
        printf("[+++] PATH CHALLENGE is recieved by the client. index:%d\n", client_current_state->frame_index);
        break;

    case PATH_RESPONSE_FRAME:
        client_current_state->frame_type = PATH_RESPONSE_FRAME;
        client_current_state->frame_index = frame->frame_index;
        printf("[+++] PATH Response is recieved by the client. index:%d\n", client_current_state->frame_index);
        break;

    }
}

bool is_state_equal(quic_state current_state, quic_state state_to_check)
{
    return ((current_state.packet_type == state_to_check.packet_type) &
            (current_state.packet_number == state_to_check.packet_number) &
            (current_state.frame_type == state_to_check.frame_type) &
            (current_state.frame_index == state_to_check.frame_index)
            );
}

void copy_state(quic_state *dest, const quic_state *src)
{
    dest->packet_type = src->packet_type;
    dest->packet_number = src->packet_number;
    dest->frame_type = src->frame_type;
    dest->frame_index = src->frame_index;
}