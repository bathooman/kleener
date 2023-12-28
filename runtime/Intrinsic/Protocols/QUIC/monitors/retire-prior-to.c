#include "klee/Protocols/quic/quic_packets.h"
#include "klee/Protocols/quic/quic_states.h"
#include "klee/Support/Protocols/helper.h"
#include "klee/klee.h"
#include <assert.h>

/* Section 19.15
* The value in the Retire Prior To field MUST be less than or equal to 
* the value in the Sequence Number field. Receiving a value in the 
* Retire Prior To field that is greater than that in the Sequence Number 
* field MUST be treated as a connection error of type FRAME_ENCODING_ERROR.
*/

#define INITIAL 0
#define PACKET_RECEIVED 1

static STATE local_state = INITIAL;

void is_retire_less_equal_to_sequence_number_server(Packet *pkt, bool is_packet_client_generated)
{
    if (is_packet_client_generated && local_state == INITIAL)
    {
        Frame *frame = pkt->enabled_frame;
        if (frame->frame_type == NEW_CONID_FRAME)
        {
            uint8_t retire_prior_to_length = decode_variable_length(frame->body->new_connection_id->retire_prior_to);
            uint8_t *retire_prior_to_concrete = malloc(retire_prior_to_length);
            memcpy(retire_prior_to_concrete, frame->body->new_connection_id->retire_prior_to, retire_prior_to_length);

            kleener_make_symbolic(frame->body->new_connection_id->retire_prior_to, retire_prior_to_length, "retire_prior");
            klee_assume((retire_prior_to_concrete[0] & 0xc0) == (frame->body->new_connection_id->retire_prior_to[0] & 0xc0));

            uint8_t sequence_number_length = decode_variable_length(frame->body->new_connection_id->sequence_number);
            uint8_t *sequence_number_concrete = malloc(sequence_number_length);
            memcpy(sequence_number_concrete, frame->body->new_connection_id->sequence_number, sequence_number_length);

            kleener_make_symbolic(frame->body->new_connection_id->sequence_number, sequence_number_length, "sequence_number");
            klee_assume((sequence_number_concrete[0] & 0xc0) == (frame->body->new_connection_id->sequence_number[0] & 0xc0));

            klee_assume(encoded_length_to_int(frame->body->new_connection_id->retire_prior_to, retire_prior_to_length) >
                        encoded_length_to_int(frame->body->new_connection_id->sequence_number, sequence_number_length));
            local_state = PACKET_RECEIVED;   
        }
    }
    else if (!is_packet_client_generated && local_state == PACKET_RECEIVED)
    {
        assert(is_returned_error_code_correct(pkt, FRAME_ENCODING_ERROR));
    }
}

void is_retire_less_equal_to_sequence_number_client(Packet *pkt, bool is_packet_client_generated)
{
    if (!is_packet_client_generated && local_state == INITIAL)
    {
        Frame *frame = pkt->enabled_frame;
        if (frame->frame_type == NEW_CONID_FRAME)
        {
            uint8_t retire_prior_to_length = decode_variable_length(frame->body->new_connection_id->retire_prior_to);
            uint8_t *retire_prior_to_concrete = malloc(retire_prior_to_length);
            memcpy(retire_prior_to_concrete, frame->body->new_connection_id->retire_prior_to, retire_prior_to_length);

            kleener_make_symbolic(frame->body->new_connection_id->retire_prior_to, retire_prior_to_length, "retire_prior");
            klee_assume((retire_prior_to_concrete[0] & 0xc0) == (frame->body->new_connection_id->retire_prior_to[0] & 0xc0));

            uint8_t sequence_number_length = decode_variable_length(frame->body->new_connection_id->sequence_number);
            uint8_t *sequence_number_concrete = malloc(sequence_number_length);
            memcpy(sequence_number_concrete, frame->body->new_connection_id->sequence_number, sequence_number_length);

            kleener_make_symbolic(frame->body->new_connection_id->sequence_number, sequence_number_length, "sequence_number");
            klee_assume((sequence_number_concrete[0] & 0xc0) == (frame->body->new_connection_id->sequence_number[0] & 0xc0));

            klee_assume(encoded_length_to_int(frame->body->new_connection_id->retire_prior_to, retire_prior_to_length) >
                        encoded_length_to_int(frame->body->new_connection_id->sequence_number, sequence_number_length));
            local_state = PACKET_RECEIVED;   
        }
    }
    else if (is_packet_client_generated && local_state == PACKET_RECEIVED)
    {
        assert(is_returned_error_code_correct(pkt, FRAME_ENCODING_ERROR));
    }
}

bool retire_less_equal_to_sequence_number_enabling_predicate(quic_state state)
{
    return (state.frame_type == NEW_CONID_FRAME);
}