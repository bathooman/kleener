#ifndef QUIC_PACKETS_H
#define QUIC_PACKETS_H

typedef struct Packet_struct Packet;
typedef struct Frame_struct Frame;

#include "stdint.h"
#include "memory.h"
#include <stdbool.h>
#include "klee/Protocols/quic/quic_monitors.h"
#include "klee/Protocols/quic/quic_states.h"

#define IV_SIZE 16

// Packets
#define INITIAL_PACKET 0x00 
#define RTT0_PACKET 0x01
#define HANDSHAKE_PACKET 0x02
#define RETRY_PACKET 0x03 
#define RTT1_PACKET 0x04

// Frames 
#define PADDING_FRAME 0x0
#define PING_FRAME 0x01
#define ACK_FRAME_START 0x02
#define ACK_FRAME_END 0x03
#define STOP_SENDING_FRAME 0x05
#define CRYPTO_FRAME 0x06
#define NEW_TOKEN_FRAME 0x07
#define STREAM_FRAME_START 0x08
#define STREAM_FRAME_END 0x0f
#define NEW_CONID_FRAME 0x18
#define HANDSHAKE_DONE_FRAME 0x1e
#define CONNECTION_CLOSE_START 0x1c
#define CONNECTION_CLOSE_END 0x1d
#define PATH_CHALLENGE_FRAME 0x1a
#define PATH_RESPONSE_FRAME 0x1b
#define ACK_FREQUENCY_FRAME 0xAF

// Error Codes
#define PROTOCOL_VIOLATION 0x0a
#define FRAME_ENCODING_ERROR 0x07
#define FLOW_CONTROL_ERROR 0x03

typedef struct
{
    size_t crypto_num;
    size_t ack_num;
    size_t padding_num;
    size_t new_token_num;
    size_t new_conid_num;
    size_t stream_num;
    size_t done_num;
    size_t conn_close_num;
    size_t ping_num;
}Stats;

typedef struct
{
    uint8_t *sequence_number;
    uint8_t *packet_tolerance;
    uint8_t *max_delay;

}ACK_FREQ;

typedef struct
{
    uint8_t data[8];
}PATH_CHALLENGE;

typedef struct
{
    uint8_t data[8];
}PATH_RESPONSE;

typedef struct
{
    uint8_t *largest_acked;
    uint8_t *ack_delay;
    uint8_t *ack_range_count;
    uint8_t *first_ack_range;
    uint8_t *ECT0_count;
    uint8_t *ECT1_count;
    uint8_t *ECN_CE_count;
}ACK;

typedef struct 
{
    uint8_t *error_code;
    uint8_t *frame_type;
    uint8_t *reason_length;
    uint8_t *reason;
}CONNECTION_CLOSE;

typedef struct
{
    uint8_t *token_length;
    uint8_t *token;
}NEW_TOKEN;

typedef struct
{
    uint8_t *sequence_number;
    uint8_t *retire_prior_to;
    uint8_t length;
    uint8_t *connection_id;
    uint8_t stateless_reset_token[16];
}NEW_CONNECTION_ID;

typedef struct
{
    uint8_t *stream_id;
    uint8_t *offset;
    uint8_t *length;
    uint8_t *data;
}STREAM;


typedef union
{
    ACK *ack;
    CONNECTION_CLOSE *connection_close;
    NEW_TOKEN *new_token;
    NEW_CONNECTION_ID *new_connection_id;
    STREAM *stream;
    ACK_FREQ *ack_freq;
    PATH_CHALLENGE *path_challenge;
    PATH_RESPONSE *path_response;
}Body;

struct Frame_struct
{
    uint8_t frame_type;
    uint8_t frame_index;
    size_t payload_length;
    uint8_t *payload;
    Body *body;
    struct Frame_struct *next_frame;

};

struct Packet_struct
{
    uint8_t base;
    uint8_t version[4];
    uint8_t destination_id_length;
    uint8_t *destination_id;
    uint8_t source_id_length;
    uint8_t *source_id;
    uint8_t token_length;
    uint8_t *token;
    uint8_t *payload_length;
    uint8_t *packet_number;
    uint8_t *payload;
    struct Frame_struct *enabled_frame;
    struct Frame_struct *frame;
    Stats stats;

};

int process_packet(uint8_t *datagram, Packet *packet, size_t *off, size_t datagram_size, bool is_client_originated);
int serialize_packet(const Packet *packet, const Packet *shadow_packet, uint8_t **out_buff, bool is_client_originated);
int decode_packet_type(const uint8_t *base);
uint8_t decode_variable_length(const uint8_t *src);
bool is_header_long(const uint8_t *base);
int decode_packet_number_length(const uint8_t *base);
size_t encoded_length_to_int(const uint8_t *src, const size_t src_length);
bool is_returned_error_code_correct(Packet *pkt, uint8_t expected_error_code);
void output_packet_info(Packet *pkt);
bool is_ack_packet_contains_pn(Packet *pkt, uint64_t pn_number);
#endif //QUIC_PACKETS_H