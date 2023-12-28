#include "klee/Protocols/quic/quic_packets.h"
#include "klee/Protocols/quic/quic_states.h"
#include "klee/Support/Protocols/helper.h"
#include "klee/klee.h"
#include <assert.h>

/* Section 19.8
* The largest offset delivered on a stream -- the sum of the offset and data length -- 
* cannot exceed 2^62-1, as it is not possible to provide flow control credit for that data. 
* Receipt of a frame that exceeds this limit MUST be treated as a connection error of type 
* FRAME_ENCODING_ERROR or FLOW_CONTROL_ERROR.
*/

#define Max_Valid_Value 4.611686e+18

#define INITIAL 0
#define PACKET_RECEIVED 1

static STATE local_state = INITIAL;

void is_oversized_stream_handled_correctly_server(Packet *pkt, bool is_packet_client_generated)
{
    if (is_packet_client_generated && local_state == INITIAL)
    {
        Frame *frame = pkt->enabled_frame;
        if ((frame->frame_type >= STREAM_FRAME_START) &&
                (frame->frame_type <= STREAM_FRAME_END))
        {
            bool offset_exists = ((frame->frame_type & 0x04) == 0x04);
            bool length_exists = ((frame->frame_type & 0x02) == 0x02);

            if (length_exists && !offset_exists)
            {
                uint8_t length_length = decode_variable_length(frame->body->stream->length);
                uint8_t *concrete_length = malloc(length_length);
                memcpy(concrete_length, frame->body->stream->length, length_length);

                kleener_make_symbolic(frame->body->stream->length, length_length, "data_length");
                klee_assume((frame->body->stream->length[0] & 0xc0) == (concrete_length[0] & 0xc0));

                klee_assume(encoded_length_to_int(frame->body->stream->length, length_length) > Max_Valid_Value);
                local_state = PACKET_RECEIVED;
            }
        }
    }
    else if (!is_packet_client_generated && local_state == PACKET_RECEIVED)
    {
        assert(is_returned_error_code_correct(pkt, FRAME_ENCODING_ERROR) || 
               is_returned_error_code_correct(pkt, FLOW_CONTROL_ERROR));
    }
}

void is_oversized_stream_handled_correctly_client(Packet *pkt, bool is_packet_client_generated)
{
    if (!is_packet_client_generated && local_state == INITIAL)
    {
        Frame *frame = pkt->enabled_frame;
        if ((frame->frame_type >= STREAM_FRAME_START) &&
                (frame->frame_type <= STREAM_FRAME_END))
        {
            bool offset_exists = ((frame->frame_type & 0x04) == 0x04);
            bool length_exists = ((frame->frame_type & 0x02) == 0x02);

            if (length_exists && !offset_exists)
            {
                uint8_t length_length = decode_variable_length(frame->body->stream->length);
                uint8_t *concrete_length = malloc(length_length);
                memcpy(concrete_length, frame->body->stream->length, length_length);

                kleener_make_symbolic(frame->body->stream->length, length_length, "data_length");
                klee_assume((frame->body->stream->length[0] & 0xc0) == (concrete_length[0] & 0xc0));

                klee_assume(encoded_length_to_int(frame->body->stream->length, length_length) > Max_Valid_Value);
                local_state = PACKET_RECEIVED;
            }

        }
    }
    else if (is_packet_client_generated && local_state == PACKET_RECEIVED)
    {
        assert(is_returned_error_code_correct(pkt, FRAME_ENCODING_ERROR) || 
               is_returned_error_code_correct(pkt, FLOW_CONTROL_ERROR));
    }
}

bool oversized_stream_enabling_predicate(quic_state state)
{
    return ((state.frame_type >= STREAM_FRAME_START) AND 
            (state.frame_type <= STREAM_FRAME_END)
            );
}