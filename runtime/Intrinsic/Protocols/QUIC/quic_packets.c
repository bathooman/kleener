#include "klee/Protocols/quic/quic_packets.h"
#include "klee/Protocols/quic/quic_states.h"
#include "klee/Protocols/quic/quic_monitors.h"
#include "klee/Support/Protocols/helper.h"
#include <stdint.h>
#include <stdio.h>
#include <memory.h>
#include <errno.h>
#include <stdlib.h>
#include <assert.h>
#include <klee/klee.h>
#include <stdbool.h>
#include <inttypes.h>

int decode_packet_type(const uint8_t *base)
{
    return ((*base) & (0x30)) >> 4;
}

bool is_header_long(const uint8_t *base)
{
    return ((*base & 0x80) == 0x80);
}

int decode_packet_number_length(const uint8_t *base)
{
    return ((*base) & 0x3) + 1;
}

uint8_t decode_variable_length(const uint8_t *src)
{
    uint8_t prefix = *src >> 6;
    return (1 <<  prefix);
}

size_t encoded_length_to_int(const uint8_t *src, const size_t src_length)
{
    uint8_t *temp = malloc(src_length);
    memcpy(temp, src, src_length);
    *temp &= 0x3f;
    uint64_t ret = byte_to_int(temp, src_length);
    free(temp);
    return ret;
}

static uint8_t stop_sending_index = 0;
static int process_stop_sending_frame(uint8_t **msg, Frame *frame, size_t *off)
{
    *msg += 1; // Get past the frame type
    uint8_t stream_id_length = decode_variable_length(*msg);
    uint8_t error_code_length = decode_variable_length(*msg + stream_id_length);
    frame->payload_length = stream_id_length + error_code_length;
    frame->payload = malloc(stream_id_length + error_code_length);
    memcpy(frame->payload, *msg, stream_id_length + error_code_length);
    *msg += stream_id_length + error_code_length;
    *off += 1 + stream_id_length + error_code_length;

    frame->frame_index = stop_sending_index;
    stop_sending_index += 1;
    return 0;
}

static uint8_t crypto_index = 0;
static int process_crypto_frame(uint8_t **msg, Frame *frame, size_t *off)
{
    *msg += 1; // Get past the frame type
    uint8_t crypto_offset_length = decode_variable_length(*msg);
    uint8_t crypto_frame_length_length = decode_variable_length(*msg + crypto_offset_length);
    uint8_t *crypto_frame_length;
    crypto_frame_length = malloc(crypto_frame_length_length);
    memcpy(crypto_frame_length, *msg + crypto_offset_length, crypto_frame_length_length);
    size_t decoded_crypto_frame_length = encoded_length_to_int(crypto_frame_length, crypto_frame_length_length);
    free(crypto_frame_length);
    decoded_crypto_frame_length += crypto_frame_length_length + crypto_offset_length; // Length field and Offset field
    frame->payload_length = decoded_crypto_frame_length;
    frame->payload = malloc(decoded_crypto_frame_length);
    memcpy(frame->payload, *msg, decoded_crypto_frame_length);
    *msg += decoded_crypto_frame_length;
    *off += 1 + decoded_crypto_frame_length;

    frame->frame_index = crypto_index;
    crypto_index += 1;
    return 0;
}

static uint8_t padding_index = 0;
static int process_padding_frame(uint8_t **msg, Frame *frame, size_t *off, size_t payload_size)
{
    *msg += 1; // Get past the frame type

    /*
     * Padding always follows in the end of a QUIC packet. So we also subtract the IV length from it.
     * IV_Length = 16
     */
    size_t padding_length = payload_size - *off - 1 - 16; // minus 1 byte of frame type
    frame->payload_length = padding_length;
    frame->payload = malloc(padding_length);
    memcpy(frame->payload, *msg, padding_length);
    *msg += padding_length;
    *off += padding_length + 1;

    frame->frame_index = padding_index;
    padding_index += 1;
    return 0;
}

static uint8_t ack_index = 0;
static int process_ack_frame(uint8_t **msg, Frame *frame, size_t *off)
{
    *msg += 1; // Get past the frame type
    uint8_t *pointer_to_beginning = *msg;

    // Parsing Largest Acknowledged field
    size_t largest_ack_length = decode_variable_length(*msg);
    frame->body->ack->largest_acked = malloc(largest_ack_length);
    memcpy(frame->body->ack->largest_acked, *msg, largest_ack_length);
    *msg += largest_ack_length;

    // Parsing Ack Delay field
    size_t ack_delay_length = decode_variable_length(*msg);
    frame->body->ack->ack_delay = malloc(ack_delay_length);
    memcpy(frame->body->ack->ack_delay, *msg, ack_delay_length);
    *msg += ack_delay_length;

    // Parsing ACK Range Count field
    size_t ack_range_count_length = decode_variable_length(*msg);
    frame->body->ack->ack_range_count = malloc(ack_range_count_length);
    memcpy(frame->body->ack->ack_range_count, *msg, ack_range_count_length);
    *msg += ack_range_count_length;

    // Parsing First ACK Range field
    size_t first_ack_range_length = decode_variable_length(*msg);
    frame->body->ack->first_ack_range = malloc(first_ack_range_length);
    memcpy(frame->body->ack->first_ack_range, *msg, first_ack_range_length);
    *msg += first_ack_range_length;

    if (frame->frame_type == ACK_FRAME_END) //ECN Counts
    {
        // Parsing ECT0 Count
        size_t ect0_count_size = decode_variable_length(*msg);
        frame->body->ack->ECT0_count = malloc(ect0_count_size);
        memcpy(frame->body->ack->ECT0_count, *msg, ect0_count_size);
        *msg += ect0_count_size;

        // Parsing ECT1 Count
        size_t ect1_count_size = decode_variable_length(*msg);
        frame->body->ack->ECT1_count = malloc(ect1_count_size);
        memcpy(frame->body->ack->ECT1_count, *msg, ect1_count_size);
        *msg += ect1_count_size;

        // Parsing ECN-CE Count
        size_t ecnce_count_size = decode_variable_length(*msg);
        frame->body->ack->ECN_CE_count = malloc(ecnce_count_size);
        memcpy(frame->body->ack->ECN_CE_count, *msg, ecnce_count_size);
        *msg += ecnce_count_size;
    }

    // Storing payload length
    frame->payload_length = *msg - pointer_to_beginning;
    frame->payload = malloc(frame->payload_length); // Size of an ACK frame minus frame type
    memcpy(frame->payload, pointer_to_beginning, frame->payload_length);

    *off += frame->payload_length + 1;

    frame->frame_index = ack_index;
    ack_index += 1;
    return 0;
}

static uint8_t new_token_index = 0;
static int process_new_token_frame(uint8_t **msg, Frame *frame, size_t *off)
{
    *msg += 1; // Get past the frame type
    uint8_t *pointer_to_beginning = *msg;

    // Parsing token length
    uint8_t token_length_length = decode_variable_length(*msg);
    frame->body->new_token->token_length = malloc(token_length_length);
    memcpy(frame->body->new_token->token_length, *msg, token_length_length);
    *msg += token_length_length;

    // Parsing token
    size_t token_length = encoded_length_to_int(frame->body->new_token->token_length, token_length_length);
    frame->body->new_token->token = malloc(token_length);
    memcpy(frame->body->new_token->token, *msg, token_length);
    *msg += token_length;

    // Storing payload length
    frame->payload_length = *msg - pointer_to_beginning;
    frame->payload = malloc(frame->payload_length); // Size of an ACK frame minus frame type
    memcpy(frame->payload, pointer_to_beginning, frame->payload_length);

    *off += frame->payload_length + 1;

    frame->frame_index = new_token_index;
    new_token_index += 1;
    return 0;
}

static uint8_t new_conid_index = 0;
static int process_new_conid_frame(uint8_t **msg, Frame *frame, size_t *off)
{
    *msg += 1; // Get past the frame type
    uint8_t *pointer_to_beginning = *msg;

    // Parsing the sequence number
    uint8_t sequence_number_length = decode_variable_length(*msg);
    frame->body->new_connection_id->sequence_number = malloc(sequence_number_length);
    memcpy(frame->body->new_connection_id->sequence_number, *msg, sequence_number_length);
    *msg += sequence_number_length;

    // Parsing Retire Prior to
    uint8_t retire_prior_to_length = decode_variable_length(*msg);
    frame->body->new_connection_id->retire_prior_to = malloc(retire_prior_to_length);
    memcpy(frame->body->new_connection_id->retire_prior_to, *msg, retire_prior_to_length);
    *msg += retire_prior_to_length;

    // Parsing Length
    frame->body->new_connection_id->length = **msg;
    *msg += 1;

    // Parsing Connection ID
    frame->body->new_connection_id->connection_id = malloc(frame->body->new_connection_id->length);
    memcpy(frame->body->new_connection_id->connection_id, *msg, frame->body->new_connection_id->length);
    *msg += frame->body->new_connection_id->length;

    // Parsing stateless token
    memcpy(frame->body->new_connection_id->stateless_reset_token, *msg, sizeof(frame->body->new_connection_id->stateless_reset_token));
    *msg += sizeof(frame->body->new_connection_id->stateless_reset_token);

    // Storing payload length
    frame->payload_length = *msg - pointer_to_beginning;
    frame->payload = malloc(frame->payload_length); // Size of an ACK frame minus frame type
    memcpy(frame->payload, pointer_to_beginning, frame->payload_length);

    *off += frame->payload_length + 1;

    frame->frame_index = new_conid_index;
    new_conid_index += 1;
    return 0;
}

static uint8_t stream_index = 0;
static int process_stream_frame(uint8_t **msg, Frame *frame, size_t *off)
{
    bool offset_exists = ((frame->frame_type & 0x04) == 0x04);
    bool length_exists = ((frame->frame_type & 0x02) == 0x02);
    uint8_t length_length;

    *msg += 1; // Get past the frame type
    uint8_t *pointer_to_beginning = *msg;

    // Parse the Stream ID
    uint8_t stream_id_length = decode_variable_length(*msg);
    frame->body->stream->stream_id = malloc(stream_id_length);
    memcpy(frame->body->stream->stream_id, *msg, stream_id_length);
    *msg += stream_id_length;

    // Parse the offset
    if (offset_exists)
    {
        uint8_t offset_length = decode_variable_length(*msg);
        frame->body->stream->offset = malloc(offset_length);
        memcpy(frame->body->stream->offset, *msg, offset_length);
        *msg += offset_length;
    }

    // Parse the length
    if (length_exists)
    {
        length_length = decode_variable_length(*msg);
        frame->body->stream->length = malloc(length_length);
        memcpy(frame->body->stream->length, *msg, length_length);
        *msg += length_length;
    }
    else
    {
        printf("Error: Stream Frame with len bit 0 is not supported!\n");
        exit(0);
    }
    // Storing the data
    size_t data_length = encoded_length_to_int(frame->body->stream->length, length_length);
    frame->body->stream->data = malloc(data_length);
    memcpy(frame->body->stream->data, *msg, data_length);
    *msg += data_length;

    // Storing payload length
    frame->payload_length = *msg - pointer_to_beginning;
    frame->payload = malloc(frame->payload_length); // Size of an ACK frame minus frame type
    memcpy(frame->payload, pointer_to_beginning, frame->payload_length);

    *off += frame->payload_length + 1;

    frame->frame_index = stream_index;
    stream_index += 1;
    return 0;
}

static uint8_t connection_close_index = 0;
static int process_connection_close_frame(uint8_t **msg, Frame *frame, size_t *off)
{
    *msg += 1; // Get past the frame type
    uint8_t *pointer_to_beginning = *msg;

    // Parsing error code
    uint8_t error_code_length = decode_variable_length(*msg);
    frame->body->connection_close->error_code = malloc(error_code_length);
    memcpy(frame->body->connection_close->error_code, *msg, error_code_length);
    *msg += error_code_length;

    if (frame->frame_type == CONNECTION_CLOSE_START)
    {
        // Parsing the field for the frame type caused the error
        uint8_t frame_type_length = decode_variable_length(*msg);
        frame->body->connection_close->frame_type = malloc(frame_type_length);
        memcpy(frame->body->connection_close->frame_type, *msg, frame_type_length);
        *msg += frame_type_length;
    }
    
    // Parsing Reason Phrase Length
    uint8_t reason_length_length = decode_variable_length(*msg);
    frame->body->connection_close->reason_length = malloc(reason_length_length);
    memcpy(frame->body->connection_close->reason_length, *msg, reason_length_length);
    *msg += reason_length_length;

    // Parsing Reason Phrase
    size_t reason_size = encoded_length_to_int(frame->body->connection_close->reason_length, reason_length_length);
    frame->body->connection_close->reason = malloc(reason_size);
    memcpy(frame->body->connection_close->reason, *msg, reason_size);
    *msg += reason_size;

    // Storing payload length
    frame->payload_length = *msg - pointer_to_beginning;
    frame->payload = malloc(frame->payload_length); // Size of an CONNECTION CLOSE frame minus frame type
    memcpy(frame->payload, pointer_to_beginning, frame->payload_length);

    *off += frame->payload_length + 1;

    frame->frame_index = connection_close_index;
    connection_close_index += 1;
    return 0;
}

static uint8_t ack_freq_index = 0;
static int process_ack_frequency(uint8_t **msg, Frame *frame, size_t *off)
{
    uint8_t *pointer_to_beginning = *msg;

    uint8_t sequence_number_length = decode_variable_length(*msg);
    frame->body->ack_freq->sequence_number = malloc(sequence_number_length);
    memcpy(frame->body->ack_freq->sequence_number, *msg, sequence_number_length);
    *msg += sequence_number_length;

    uint8_t packet_tolerance_length = decode_variable_length(*msg);
    frame->body->ack_freq->packet_tolerance = malloc(packet_tolerance_length);
    memcpy(frame->body->ack_freq->packet_tolerance, *msg, packet_tolerance_length);
    *msg += packet_tolerance_length;

    uint8_t max_delay_length = decode_variable_length(*msg);
    frame->body->ack_freq->max_delay = malloc(max_delay_length);
    memcpy(frame->body->ack_freq->max_delay, *msg, max_delay_length);
    *msg += max_delay_length;

    // Storing payload length
    frame->payload_length = *msg - pointer_to_beginning;
    frame->payload = malloc(frame->payload_length); // Size of an ACK_FREQ frame minus frame type
    memcpy(frame->payload, pointer_to_beginning, frame->payload_length);

    *off += frame->payload_length + 1;

    frame->frame_index = ack_freq_index;
    ack_freq_index += 1;

    return 0;
}

static uint8_t path_challenge_index = 0;
static int process_path_challenge_frame(uint8_t **msg, Frame *frame, size_t *off)
{
    *msg += 1; // Get past the frame type
    uint8_t *pointer_to_beginning = *msg;

    memcpy(frame->body->path_challenge->data, *msg, sizeof(frame->body->path_challenge->data));
    *msg += sizeof(frame->body->path_challenge->data);

    // Storing payload length
    frame->payload_length = *msg - pointer_to_beginning;
    frame->payload = malloc(frame->payload_length); // Size of an Path Challenge frame minus frame type
    memcpy(frame->payload, pointer_to_beginning, frame->payload_length);

    *off += frame->payload_length + 1;

    frame->frame_index = path_challenge_index;
    path_challenge_index += 1;

    return 0;
}

static uint8_t path_response_index = 0;
static int process_path_response_frame(uint8_t **msg, Frame *frame, size_t *off)
{
    *msg += 1; // Get past the frame type
    uint8_t *pointer_to_beginning = *msg;

    memcpy(frame->body->path_response->data, *msg, sizeof(frame->body->path_response->data));
    *msg += sizeof(frame->body->path_response->data);

    // Storing payload length
    frame->payload_length = *msg - pointer_to_beginning;
    frame->payload = malloc(frame->payload_length); // Size of an Path Challenge frame minus frame type
    memcpy(frame->payload, pointer_to_beginning, frame->payload_length);

    *off += frame->payload_length + 1;
    
    frame->frame_index = path_response_index;
    path_response_index += 1;

    return 0;
}   

static int process_variable_length_frame_type(uint8_t **msg, Frame *frame, size_t *off)
{
    uint8_t frame_type_size = decode_variable_length(*msg);
    uint8_t *alloc_frame_type = malloc(frame_type_size);
    memcpy(alloc_frame_type, *msg, frame_type_size);

    uint64_t decoded_frame_type = encoded_length_to_int(alloc_frame_type, frame_type_size);

    if (decoded_frame_type == ACK_FREQUENCY_FRAME)
    {
        frame->frame_type = ACK_FREQUENCY_FRAME;
        *msg += frame_type_size; // Get past the frame type
        frame->body = malloc(sizeof(Body));
        frame->body->ack_freq = malloc(sizeof(ACK_FREQ));

        process_ack_frequency(msg, frame, off);
        free(alloc_frame_type);

    }
    else
    {
        return -1;
    }
    return 0;
}

static uint8_t handshake_done_index = 0;
static uint8_t ping_index = 0;

static int process_frames(Packet *packet, size_t payload_size)
{

    size_t off = 0;
    uint8_t *msg = packet->payload;
    Frame **previous_next_pointer = &packet->frame;
    while (off != payload_size - IV_SIZE)
    {
        Frame *frame = *previous_next_pointer = malloc(sizeof(Frame));
        frame->next_frame = NULL;
        previous_next_pointer = &frame->next_frame;
        switch (*msg) {
            case STOP_SENDING_FRAME:
                frame->frame_type = STOP_SENDING_FRAME;
                process_stop_sending_frame(&msg, frame, &off);
                break;

            case CRYPTO_FRAME:
                frame->frame_type = CRYPTO_FRAME;
                process_crypto_frame(&msg, frame, &off);
                break;

            case PADDING_FRAME:
                frame->frame_type = PADDING_FRAME;
                process_padding_frame(&msg, frame, &off, payload_size);
                break;
            case PING_FRAME:
                frame->frame_type = PING_FRAME;
                msg += 1;
                off += 1;

                frame->frame_index = ping_index;
                ping_index += 1;
                break;

            case ACK_FRAME_START ... ACK_FRAME_END:
                frame->frame_type = *msg;
                frame->body = malloc(sizeof(Body));
                frame->body->ack = malloc(sizeof(ACK));
                process_ack_frame(&msg, frame, &off);
                break;

            case NEW_TOKEN_FRAME:
                frame->frame_type = *msg;
                frame->body = malloc(sizeof(Body));
                frame->body->new_token = malloc(sizeof(NEW_TOKEN));
                process_new_token_frame(&msg, frame, &off);
                break;

            case NEW_CONID_FRAME:
                frame->frame_type = *msg;
                frame->body = malloc(sizeof(Body));
                frame->body->new_connection_id = malloc(sizeof(NEW_CONNECTION_ID));
                process_new_conid_frame(&msg, frame, &off);
                break;
            case STREAM_FRAME_START ... STREAM_FRAME_END:
                frame->frame_type = *msg;
                frame->body = malloc(sizeof(Body));
                frame->body->stream = malloc(sizeof(STREAM));
                process_stream_frame(&msg, frame, &off);
                break;

            case HANDSHAKE_DONE_FRAME:
                frame->frame_type = *msg;
                msg += 1;
                off += 1;

                frame->frame_index = handshake_done_index;
                handshake_done_index += 1;
                break;
            
            case CONNECTION_CLOSE_START ... CONNECTION_CLOSE_END:
                frame->frame_type = *msg;
                frame->body = malloc(sizeof(Body));
                frame->body->connection_close = malloc(sizeof(CONNECTION_CLOSE));
                process_connection_close_frame(&msg, frame, &off);
                break;

            case PATH_CHALLENGE_FRAME:
                frame->frame_type = *msg;
                frame->body = malloc(sizeof(Body));
                frame->body->path_challenge = malloc(sizeof(PATH_CHALLENGE));
                process_path_challenge_frame(&msg, frame, &off);
                break;

            case PATH_RESPONSE_FRAME:
                frame->frame_type = *msg;
                frame->body = malloc(sizeof(Body));
                frame->body->path_response = malloc(sizeof(PATH_RESPONSE));
                process_path_response_frame(&msg, frame, &off);
                break;
                
            default:
                if(process_variable_length_frame_type(&msg, frame, &off) == 0)
                    continue;
                printf("Frame Type:%d\n", *msg);
                return -1;
        }
    }
    return 0;
}

static bool is_client_conid_exist = false;
static bool is_server_conid_exist = false;

int process_packet(uint8_t *datagram, Packet *packet, size_t *off, size_t datagram_size, bool is_client_originated) {

    uint8_t *msg = (uint8_t *) datagram + *off;
    uint8_t *pointer_to_start = (uint8_t *) datagram + *off;
    packet->base = (*msg);
    msg += 1; // Get past the first byte
    if (is_header_long(&packet->base))
    {
        memcpy(packet->version, msg, 4);
        msg += 4; // Get past the version

        uint8_t destination_id_length = (*msg);
        msg += 1; // Get past the Destination ID Length
        packet->destination_id_length = destination_id_length;
        if (destination_id_length > 0) {
            packet->destination_id = malloc(destination_id_length);
            memcpy(packet->destination_id, msg, destination_id_length);
            msg += destination_id_length;
        }
        uint8_t source_id_length = *msg;
        msg += 1; // Get past the Source ID Length        
        packet->source_id_length = source_id_length;
        if (source_id_length > 0) {
            packet->source_id = malloc(source_id_length);
            memcpy(packet->source_id, msg, source_id_length);
            msg += source_id_length;
        }
        if (byte_to_int(packet->version, 4) == 0)
        {
            // Version Negotiation Packet
            packet->payload_length = malloc(1); // One byte is enough for the length of payload
            uint8_t payload_length = datagram_size - (msg - pointer_to_start);
            memcpy(packet->payload_length, &payload_length, 1);
            // packet->payload_length = &payload_length;
            packet->payload = malloc(payload_length);
            memcpy(packet->payload, msg, payload_length);
            *off += (msg - pointer_to_start) + payload_length;

            return 0; // Upon success
        }

        // We check if is it an Initial?
        if (decode_packet_type(&packet->base) == 0x0)
        {
            uint8_t token_length = *msg;
            packet->token_length = token_length;
            msg += 1; // Get past the Token Length
            if (token_length > 0)
            {
                packet->token = malloc(token_length);
                memcpy(packet->token, msg, token_length);
                msg += token_length; // Get past the Token
            }

            // Let us check if the side is providing its connectionID
            // We will use it later for parsing the packets with short header
            if (packet->source_id_length > 0)
            {
                (is_client_originated) ? (is_client_conid_exist = true) : (is_server_conid_exist = true);
            }
        }

        /* The length of the Packet length will be determined by the first two bits */
        uint8_t packet_length_length = decode_variable_length(msg);
        packet->payload_length = malloc(packet_length_length);
        memcpy(packet->payload_length, msg, packet_length_length);
        msg += packet_length_length; // Get past the packet length field
        size_t payload_length = encoded_length_to_int(packet->payload_length, packet_length_length);
        uint8_t pn_size = decode_packet_number_length(&packet->base);
        payload_length -= pn_size; // Update the payload length to exclude the packet number
        packet->packet_number = malloc(pn_size);
        memcpy(packet->packet_number, msg, pn_size);
        msg += pn_size; // Get past the packet number
        packet->payload = malloc(payload_length);
        memcpy(packet->payload, msg, payload_length);
        if(process_frames(packet, payload_length) < 0)
        {
            printf("Processing frames failed!\n");
            exit(-1);
        }
        size_t encrypted_len = msg - pointer_to_start;
        *off += encrypted_len + payload_length;
        return 0; // Upon success

    }
    else if (!is_header_long(&packet->base))
    {
        uint8_t pn_size = decode_packet_number_length(&packet->base);
        packet->packet_number = malloc(pn_size);

        if ((is_client_originated && is_server_conid_exist) ||
            (!is_client_originated && is_client_conid_exist))
        {
            size_t connection_id_length = 8;
            /*
            * Todo: The length of connection ID is assumed!
            */
            packet->destination_id = malloc(connection_id_length);
            memcpy(packet->destination_id, msg, connection_id_length);
            msg += connection_id_length; // Get past the connection id
            memcpy(packet->packet_number, msg, pn_size);
            msg += pn_size; // Get past the packet number
            uint16_t payload_length = datagram_size - *off - connection_id_length - pn_size - 1; // 1 is the length of base
            /*
            * Todo: It is not clear if the length of the length field is two
            */
            packet->payload_length = malloc(2);
            int_to_uint16(packet->payload_length, payload_length);
            packet->payload = malloc(payload_length);
            memcpy(packet->payload, msg, payload_length);
            if(process_frames(packet, payload_length) < 0)
            {
                printf("Processing frames failed!\n");
                exit(-1);
            }
            size_t encrypted_len = msg - pointer_to_start;
            *off += encrypted_len + payload_length;

            return 0; // Upon success
        }
        else
        {
            memcpy(packet->packet_number, msg, pn_size);
            msg += pn_size; // Get past the packet number
            uint16_t payload_length = datagram_size - *off - pn_size - 1; // 1 is the length of base
            /*
            * Todo: It is not clear if the length of the length field is two
            */
            packet->payload_length = malloc(2);
            int_to_uint16(packet->payload_length, payload_length);
            packet->payload = malloc(payload_length);
            memcpy(packet->payload, msg, payload_length);
            if(process_frames(packet, payload_length) < 0)
            {
                printf("Processing frames failed!\n");
                exit(-1);
            }
            size_t encrypted_len = msg - pointer_to_start;
            *off += encrypted_len + payload_length;

            return 0; // Upon success
        }
    }
    else
        return -1;
}

static int serialize_stop_sending_frame(uint8_t **outbuffer, Frame *frame, Frame *shadow_frame)
{
    *outbuffer += 1; // Get past the frame type
    memcpy(*outbuffer, frame->payload, shadow_frame->payload_length);
    *outbuffer += shadow_frame->payload_length;
    return 0;

}

static int serialize_crypto_frame(uint8_t **outbuffer, Frame *frame, Frame *shadow_frame)
{
    *outbuffer += 1; // Get past the frame type
    memcpy(*outbuffer, frame->payload, shadow_frame->payload_length);
    *outbuffer += shadow_frame->payload_length;
    return 0;

}

static int serialize_padding_frame(uint8_t **outbuffer, Frame *frame, Frame *shadow_frame)
{
    *outbuffer += 1; // Get past the frame type
    memcpy(*outbuffer, frame->payload, shadow_frame->payload_length);
    *outbuffer += shadow_frame->payload_length;
    return 0;
}

static int serialize_ack_frame(uint8_t **outbuffer, Frame *frame, Frame *shadow_frame)
{
    *outbuffer += 1; // Get past the frame type

    // Serialize the Largest Acknowledged field
    size_t largest_acked_length = decode_variable_length(shadow_frame->body->ack->largest_acked);
    memcpy(*outbuffer, frame->body->ack->largest_acked, largest_acked_length);
    *outbuffer += largest_acked_length;

    // Serialize the ACK Delay field
    size_t ack_delay_length  = decode_variable_length(shadow_frame->body->ack->ack_delay);
    memcpy(*outbuffer, frame->body->ack->ack_delay, ack_delay_length);
    *outbuffer += ack_delay_length;

    // Serialize the ACK Range Count field
    size_t ack_range_count_length = decode_variable_length(shadow_frame->body->ack->ack_range_count);
    memcpy(*outbuffer, frame->body->ack->ack_range_count, ack_range_count_length);
    *outbuffer += ack_range_count_length;

    // Serialize the First ACK Range field
    size_t first_ack_range_length = decode_variable_length(shadow_frame->body->ack->first_ack_range);
    memcpy(*outbuffer, frame->body->ack->first_ack_range, first_ack_range_length);
    *outbuffer += first_ack_range_length;

    if (shadow_frame->frame_type == ACK_FRAME_END) //ECN Counts
    {
        // Serialize ECT0 Count
        size_t ect0_count_size = decode_variable_length(shadow_frame->body->ack->ECT0_count);
        memcpy(*outbuffer, frame->body->ack->ECT0_count, ect0_count_size);
        *outbuffer += ect0_count_size;

        // Serialize ECT1 Count
        size_t ect1_count_size = decode_variable_length(shadow_frame->body->ack->ECT1_count);
        memcpy(*outbuffer, frame->body->ack->ECT1_count, ect1_count_size);
        *outbuffer += ect1_count_size;

        // Serialize ECN-CE Count
        size_t ecnce_count_size = decode_variable_length(shadow_frame->body->ack->ECN_CE_count);
        memcpy(*outbuffer, frame->body->ack->ECN_CE_count, ecnce_count_size);
        *outbuffer += ecnce_count_size;
    }

    return 0;
}

static int serialize_new_token_frame(uint8_t **outbuffer, Frame *frame, Frame *shadow_frame)
{
    *outbuffer += 1; // Get past the frame type

    // Serialize back the token length
    size_t token_length_length = decode_variable_length(shadow_frame->body->new_token->token_length);
    memcpy(*outbuffer, frame->body->new_token->token_length, token_length_length);
    *outbuffer += token_length_length;

    // Serialize back the token
    size_t token_length = encoded_length_to_int(shadow_frame->body->new_token->token_length, token_length_length);
    memcpy(*outbuffer, frame->body->new_token->token, token_length);
    *outbuffer += token_length;

    return 0;
}

static int serialize_new_conid_frame(uint8_t **outbuffer, Frame *frame, Frame *shadow_frame)
{
    *outbuffer += 1; // Get past the frame type

    // Serialize back the sequence number
    uint8_t sequence_number_length = decode_variable_length(shadow_frame->body->new_connection_id->sequence_number);
    memcpy(*outbuffer, frame->body->new_connection_id->sequence_number, sequence_number_length);
    *outbuffer += sequence_number_length;

    // Serialize back the retire prior to
    uint8_t retire_prior_to_length = decode_variable_length(shadow_frame->body->new_connection_id->retire_prior_to);
    memcpy(*outbuffer, frame->body->new_connection_id->retire_prior_to, retire_prior_to_length);
    *outbuffer += retire_prior_to_length;

    // Serialize back the length
    **outbuffer = frame->body->new_connection_id->length;
    *outbuffer += sizeof(shadow_frame->body->new_connection_id->length);

    // Serialize back the connection id
    memcpy(*outbuffer, frame->body->new_connection_id->connection_id, shadow_frame->body->new_connection_id->length);
    *outbuffer += shadow_frame->body->new_connection_id->length;

    // Serialize back the reset token
    memcpy(*outbuffer, frame->body->new_connection_id->stateless_reset_token, sizeof(shadow_frame->body->new_connection_id->stateless_reset_token));
    *outbuffer += sizeof(shadow_frame->body->new_connection_id->stateless_reset_token);

    return 0;
}

static int serialize_stream_frame(uint8_t **outbuffer, Frame *frame, Frame *shadow_frame)
{
    bool offset_exists = ((shadow_frame->frame_type & 0x04) == 0x04);
    bool length_exists = ((shadow_frame->frame_type & 0x02) == 0x02);


    *outbuffer += 1; // Get past the frame type
    
    // Serialize back the stream ID
    uint8_t id_length = decode_variable_length(shadow_frame->body->stream->stream_id);
    memcpy(*outbuffer, frame->body->stream->stream_id, id_length);
    *outbuffer += id_length;

    // Serialize the offset
    if (offset_exists)
    {
        uint8_t offset_length = decode_variable_length(shadow_frame->body->stream->offset);
        memcpy(*outbuffer, frame->body->stream->offset, offset_length);
        *outbuffer += offset_length;
    }

    // Serialize the length and the data
    if (length_exists)
    {
        uint8_t length_length = decode_variable_length(shadow_frame->body->stream->length);
        memcpy(*outbuffer, frame->body->stream->length, length_length);
        *outbuffer += length_length;

        size_t data_length = encoded_length_to_int(shadow_frame->body->stream->length, length_length);
        memcpy(*outbuffer, frame->body->stream->data, data_length);
        *outbuffer += data_length;
    }
    else
    {
        printf("Error: Stream Frame with len bit 0 is not supported!\n");
        exit(0);
    }

    return 0;
}

static int serialize_connection_close_frame(uint8_t **outbuffer, Frame *frame, Frame *shadow_frame)
{
    *outbuffer += 1; // Get past the frame type

    // Serialize Error code
    uint8_t error_code_length = decode_variable_length(shadow_frame->body->connection_close->error_code);
    memcpy(*outbuffer, frame->body->connection_close->error_code, error_code_length);
    *outbuffer += error_code_length;

    if (shadow_frame->frame_type == CONNECTION_CLOSE_START)
    {
        // Serialize the field for the frame type caused the error
        uint8_t frame_type_length = decode_variable_length(shadow_frame->body->connection_close->frame_type);
        memcpy(*outbuffer, frame->body->connection_close->frame_type, frame_type_length);
        *outbuffer += frame_type_length;
    }
    
    // Serialize reason length
    uint8_t reason_length_length = decode_variable_length(shadow_frame->body->connection_close->reason_length);
    memcpy(*outbuffer, frame->body->connection_close->reason_length, reason_length_length);
    *outbuffer += reason_length_length;

    // Serialize reason
    size_t reason_size = encoded_length_to_int(shadow_frame->body->connection_close->reason_length, reason_length_length);
    memcpy(*outbuffer, frame->body->connection_close->reason, reason_size);
    *outbuffer += reason_size;

    return 0;
}

static int serialize_ack_frequency_frame(uint8_t **outbuffer, Frame *frame, Frame *shadow_frame)
{
    *outbuffer += 1; // Get past the frame type

    uint8_t sequence_number_length = decode_variable_length(shadow_frame->body->ack_freq->sequence_number);
    memcpy(*outbuffer, frame->body->ack_freq->sequence_number, sequence_number_length);
    *outbuffer += sequence_number_length;

    uint8_t packet_tolerance_length = decode_variable_length(shadow_frame->body->ack_freq->packet_tolerance);
    memcpy(*outbuffer, frame->body->ack_freq->packet_tolerance, packet_tolerance_length);
    *outbuffer += packet_tolerance_length;

    uint8_t max_delay_length = decode_variable_length(shadow_frame->body->ack_freq->max_delay);
    memcpy(*outbuffer, frame->body->ack_freq->max_delay, max_delay_length);
    *outbuffer += max_delay_length;

    return 0;
}

static int serialize_frames(const Packet *packet, const Packet *shadow_packet, uint8_t **out_buffer)
{

    if (shadow_packet->frame == NULL)
    {
        return -1;
    }

    Frame *frame = packet->frame;
    Frame *shadow_frame = shadow_packet->frame;
    while (frame != NULL && shadow_frame != NULL)
    {
            switch (shadow_frame->frame_type)
            {
                case STOP_SENDING_FRAME:
                    **out_buffer = frame->frame_type;
                    serialize_stop_sending_frame(out_buffer, frame, shadow_frame);
                    break;

                case CRYPTO_FRAME:
                    **out_buffer = frame->frame_type;
                    serialize_crypto_frame(out_buffer, frame, shadow_frame);
                    break;

                case PADDING_FRAME:
                    **out_buffer = frame->frame_type;
                    serialize_padding_frame(out_buffer, frame, shadow_frame);
                    break;
                    
                case PING_FRAME:
                    **out_buffer = frame->frame_type;
                    *out_buffer += 1;
                    break;

                case ACK_FRAME_START ... ACK_FRAME_END:
                    **out_buffer = frame->frame_type;
                    serialize_ack_frame(out_buffer, frame, shadow_frame);
                    break;

                case NEW_TOKEN_FRAME:
                    **out_buffer = frame->frame_type;
                    serialize_new_token_frame(out_buffer, frame, shadow_frame);
                    break;

                case NEW_CONID_FRAME:
                    **out_buffer = frame->frame_type;
                    serialize_new_conid_frame(out_buffer, frame, shadow_frame);
                    break;

                case STREAM_FRAME_START ... STREAM_FRAME_END:
                    **out_buffer = frame->frame_type;
                    serialize_stream_frame(out_buffer, frame, shadow_frame);
                    break;

                case HANDSHAKE_DONE_FRAME:
                    **out_buffer = frame->frame_type;
                    *out_buffer += 1;
                    break;
                
                case CONNECTION_CLOSE_START ... CONNECTION_CLOSE_END:
                    **out_buffer = frame->frame_type;
                    serialize_connection_close_frame(out_buffer, frame, shadow_frame);
                    break;

                case ACK_FREQUENCY_FRAME:
                    **out_buffer = 0x40; // Hack for PicoQUIC
                    *out_buffer += 1;
                    **out_buffer = frame->frame_type;
                    serialize_ack_frequency_frame(out_buffer, frame, shadow_frame);
                    break;

                case PATH_CHALLENGE_FRAME:
                    **out_buffer = frame->frame_type;
                    *out_buffer += 1;
                    memcpy(*out_buffer, frame->body->path_challenge->data, sizeof(frame->body->path_challenge->data));
                    *out_buffer += sizeof(frame->body->path_challenge->data);
                    break;

                case PATH_RESPONSE_FRAME:
                    **out_buffer = frame->frame_type;
                    *out_buffer += 1;
                    memcpy(*out_buffer, frame->body->path_response->data, sizeof(frame->body->path_response->data));
                    *out_buffer += sizeof(frame->body->path_response->data);
                    break;

                default:
                    return -1;
            }
    frame = frame->next_frame;
    shadow_frame = shadow_frame->next_frame;
    }
    return 0;
}

int serialize_packet(const Packet *packet, const Packet *shadow_packet, uint8_t **out_buff, bool is_client_originated)
{
    **out_buff = packet->base;
    *out_buff += 1; // Get past the base
    if (is_header_long(&shadow_packet->base))
    {
        memcpy(*out_buff, packet->version, sizeof(packet->version));
        *out_buff += 4; // Get past the version
        **out_buff = packet->destination_id_length;
        *out_buff += 1; // Get past the destination ID length
        memcpy(*out_buff, packet->destination_id, shadow_packet->destination_id_length);
        *out_buff += shadow_packet->destination_id_length; // Get past the destination ID
        **out_buff = packet->source_id_length;
        *out_buff += 1; // Get past the source ID length
        if (shadow_packet->source_id_length > 0)
        {
            memcpy(*out_buff, packet->source_id, shadow_packet->source_id_length);
            *out_buff += shadow_packet->source_id_length; // Get past the source ID
        }

        if (byte_to_int(shadow_packet->version, 4) == 0)
        {
            // Version Negotiation Packet
            uint8_t payload_length = *packet->payload_length;
            memcpy(*out_buff, packet->payload, payload_length);
            *out_buff += payload_length;
            return 0; // Upon success
        }

        if (decode_packet_type(&shadow_packet->base) == 0x0)
        {
            **out_buff = packet->token_length;
            *out_buff += 1; // Get past the token length
            if (shadow_packet->token_length > 0)
            {
                memcpy(*out_buff, packet->token, shadow_packet->token_length);
                *out_buff += shadow_packet->token_length; // Get past the token
            }
        }
        uint8_t packet_length_length = decode_variable_length(shadow_packet->payload_length);
        uint64_t payload_length = encoded_length_to_int(shadow_packet->payload_length, packet_length_length);
        memcpy(*out_buff, packet->payload_length, packet_length_length);
        *out_buff += packet_length_length; // Get past the packet length
        uint8_t pn_size = decode_packet_number_length(&shadow_packet->base);
        memcpy(*out_buff, packet->packet_number, pn_size);
        *out_buff += pn_size; // Get past the pn
        payload_length -= pn_size;
        serialize_frames(packet, shadow_packet, out_buff);
        memcpy(*out_buff, packet->payload + payload_length - 16, 16); // Copy the IV
        *out_buff += 16;
    }
    else
    {
        uint8_t pn_size = decode_packet_number_length(&shadow_packet->base);
        if ((is_client_originated && is_server_conid_exist) ||
            (!is_client_originated && is_client_conid_exist))
        {
            /*
            * Todo: The length of connection ID is assumed!
            */
            size_t connection_id_length = 8;
            memcpy(*out_buff, packet->destination_id, connection_id_length);
            *out_buff+= connection_id_length;
            memcpy(*out_buff, packet->packet_number, pn_size);
            *out_buff += pn_size; // Get past the pn
            uint64_t payload_length = byte_to_int(packet->payload_length, 2); // Todo: packet length is assumed 2 bytes
            serialize_frames(packet, shadow_packet, out_buff);
            memcpy(*out_buff, packet->payload + payload_length - 16, 16); // Copy the IV
            *out_buff += 16;
        }
        else
        {
            
            memcpy(*out_buff, packet->packet_number, pn_size);
            *out_buff += pn_size; // Get past the pn
            uint64_t payload_length = byte_to_int(shadow_packet->payload_length, 2); // Todo: packet length is assumed 2 bytes
            serialize_frames(packet, shadow_packet, out_buff);
            memcpy(*out_buff, packet->payload + payload_length - 16, 16); // Copy the IV
            *out_buff += 16;
        }

    }
    return  0;
}

bool is_returned_error_code_correct(Packet *pkt, uint8_t expected_error_code)
{
    Frame *frame = pkt->frame;
    while (frame != NULL)
    {
        if ((frame->frame_type == CONNECTION_CLOSE_START) || (frame->frame_type == CONNECTION_CLOSE_END))
        {
            uint8_t *pkt_error_code;
            uint8_t pkt_error_code_length = decode_variable_length(frame->body->connection_close->error_code);
            pkt_error_code = malloc(pkt_error_code_length);
            memcpy(pkt_error_code, frame->body->connection_close->error_code, pkt_error_code_length);
            if (memcmp(pkt_error_code, &expected_error_code, 1) == 0)
            {
                free(pkt_error_code);
                return 1;
            }
        }
        frame = frame->next_frame;
    }
    return 0;
}

bool is_ack_packet_contains_pn(Packet *pkt, uint64_t pn_number)
{
    Frame *frame = pkt->frame;
    while (frame != NULL)
    {
        if ((frame->frame_type == ACK_FRAME_START) || (frame->frame_type == ACK_FRAME_END))
        {
            uint8_t *largest_acked;
            uint8_t *first_range;
            uint8_t largest_acked_length = decode_variable_length(frame->body->ack->largest_acked);
            largest_acked = malloc(largest_acked_length);
            memcpy(largest_acked, frame->body->ack->largest_acked, largest_acked_length);
            uint8_t first_range_length = decode_variable_length(frame->body->ack->first_ack_range);
            first_range = malloc(first_range_length);
            memcpy(first_range, frame->body->ack->first_ack_range, first_range_length);
            uint64_t decoded_largest_acked = encoded_length_to_int(largest_acked, largest_acked_length);
            uint64_t decoded_first_range = encoded_length_to_int(first_range, first_range_length);
            if ((decoded_largest_acked >= pn_number) && (pn_number >= decoded_largest_acked - decoded_first_range))
            {
                printf("the largest ack is:%"PRIu64 "while the pn_number is: %"PRIu64"\n\n", decoded_largest_acked, pn_number);
                return true;
            }
        }
        frame = frame->next_frame;
    }
    return 0;

}

void output_packet_info(Packet *pkt)
{
    uint8_t pn_size = decode_packet_number_length(&pkt->base);
    uint8_t packet_number = byte_to_int(pkt->packet_number, pn_size);

    if (byte_to_int(pkt->version, 4) == 0)
    {
        printf("[?] Version Negotiation Packet. PN:%d \n", packet_number);
        return;
    }
    
    if (is_header_long(&pkt->base))
    {
        switch (decode_packet_type(&pkt->base))
        {
        case INITIAL_PACKET:            
            printf("[?] INITIAL. PN:%d\n", packet_number);
            break;
        
        case RTT0_PACKET:
            printf("[?] 0-RTT. PN:%d\n", packet_number);
            break;

        case HANDSHAKE_PACKET:
            printf("[?] HANDSHAKE. PN:%d\n", packet_number);
            break;

        default:
            printf("Unknown Packet type:%X\n", pkt->base);
            break;
        }
    }
    else
    {
        // If the packet does not have long header, it is a 1-RTT packet
        printf("[?] 1-RTT. PN:%d\n", packet_number);
    }
}