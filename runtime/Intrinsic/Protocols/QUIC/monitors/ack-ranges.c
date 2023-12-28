#include "klee/Protocols/quic/quic_packets.h"
#include "klee/Protocols/quic/quic_states.h"
#include "klee/Support/Protocols/helper.h"
#include "klee/klee.h"
#include <assert.h>

/* Section 19.3.1
* Each ACK Range acknowledges a contiguous range of packets by indicating the number
* of acknowledged packets that precede the largest packet number in that range.
* A value of 0 indicates that only the largest packet number is acknowledged. 
* Larger ACK Range values indicate a larger range, with corresponding lower values 
* for the smallest packet number in the range. Thus, given a largest packet number
* for the range, the smallest value is determined by the following formula:
* smallest = largest - ack_range.
* If any computed packet number is negative, an endpoint MUST generate a 
* connection error of type FRAME_ENCODING_ERROR.
*/

#define INITIAL 0
#define PACKET_RECEIVED 1

static STATE local_state = INITIAL;

void is_ack_range_valid_server(Packet *pkt, bool is_packet_client_generated)
{
    if (is_packet_client_generated && local_state == INITIAL)
    {
        Frame *frame = pkt->enabled_frame;
        if (frame != NULL && (frame->frame_type == ACK_FRAME_START || frame->frame_type == ACK_FRAME_END))
        {
            uint8_t largest_acked_length = decode_variable_length(frame->body->ack->largest_acked);
            uint8_t *largest_acked = malloc(largest_acked_length);
            memcpy(largest_acked, frame->body->ack->largest_acked, largest_acked_length);

            kleener_make_symbolic(frame->body->ack->largest_acked, largest_acked_length, "largest_acked");
            klee_assume((largest_acked[0] & 0xc0) == (frame->body->ack->largest_acked[0] & 0xc0));

            uint8_t first_ack_range_length = decode_variable_length(frame->body->ack->first_ack_range);
            uint8_t *first_ack_range = malloc(first_ack_range_length);
            memcpy(first_ack_range, frame->body->ack->first_ack_range, first_ack_range_length);

            kleener_make_symbolic(frame->body->ack->first_ack_range, first_ack_range_length, "first_ack_range");
            klee_assume((first_ack_range[0] & 0xc0) == (frame->body->ack->first_ack_range[0] & 0xc0));

            klee_assume(encoded_length_to_int(frame->body->ack->largest_acked, largest_acked_length) < 
                        encoded_length_to_int(frame->body->ack->first_ack_range, first_ack_range_length));

            local_state = PACKET_RECEIVED;   
        }
        
    }
    else if (!is_packet_client_generated && local_state == PACKET_RECEIVED)
    {
        assert(is_returned_error_code_correct(pkt, FRAME_ENCODING_ERROR));
    }   
}

void is_ack_range_valid_client(Packet *pkt, bool is_packet_client_generated)
{
    if (!is_packet_client_generated && local_state == INITIAL)
    {
        Frame *frame = pkt->enabled_frame;
        if (frame != NULL && (frame->frame_type == ACK_FRAME_START || frame->frame_type == ACK_FRAME_END))
        {
            uint8_t largest_acked_length = decode_variable_length(frame->body->ack->largest_acked);
            uint8_t *largest_acked = malloc(largest_acked_length);
            memcpy(largest_acked, frame->body->ack->largest_acked, largest_acked_length);

            kleener_make_symbolic(frame->body->ack->largest_acked, largest_acked_length, "largest_acked");
            klee_assume((largest_acked[0] & 0xc0) == (frame->body->ack->largest_acked[0] & 0xc0));

            uint8_t first_ack_range_length = decode_variable_length(frame->body->ack->first_ack_range);
            uint8_t *first_ack_range = malloc(first_ack_range_length);
            memcpy(first_ack_range, frame->body->ack->first_ack_range, first_ack_range_length);

            kleener_make_symbolic(frame->body->ack->first_ack_range, first_ack_range_length, "first_ack_range");
            klee_assume((first_ack_range[0] & 0xc0) == (frame->body->ack->first_ack_range[0] & 0xc0));

            klee_assume(encoded_length_to_int(frame->body->ack->largest_acked, largest_acked_length) < 
                        encoded_length_to_int(frame->body->ack->first_ack_range, first_ack_range_length));

            local_state = PACKET_RECEIVED;                            
        }        
    }
    else if (is_packet_client_generated && local_state == PACKET_RECEIVED)
    {
        assert(is_returned_error_code_correct(pkt, FRAME_ENCODING_ERROR));
    }
}

bool ack_range_enabling_predicate(quic_state state)
{
    return (state.frame_type == ACK_FRAME_START OR
            state.frame_type == ACK_FRAME_END);
}