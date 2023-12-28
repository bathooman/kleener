#include "klee/Protocols/quic/quic_packets.h"
#include "klee/Protocols/quic/quic_states.h"
#include "klee/Support/Protocols/helper.h"
#include "klee/klee.h"
#include <assert.h>

/* Section 19.15
* An 8-bit unsigned integer containing the length of the connection ID. 
* Values less than 1 and greater than 20 are invalid and MUST be treated 
* as a connection error of type FRAME_ENCODING_ERROR.
*/

#define INITIAL 0
#define PACKET_RECEIVED 1

static STATE local_state = INITIAL;

void is_new_connection_id_length_correct_server(Packet *pkt, bool is_packet_client_generated)
{
    if (is_packet_client_generated && local_state == INITIAL)
    {
        Frame *frame = pkt->enabled_frame;
        if (frame->frame_type == NEW_CONID_FRAME)
        {
            kleener_make_symbolic(&frame->body->new_connection_id->length, 
            sizeof(frame->body->new_connection_id->length), "new_connection_id_length");

            klee_assume((frame->body->new_connection_id->length < 1) OR
                        (frame->body->new_connection_id->length > 20));

            local_state = PACKET_RECEIVED;   
        }
    }
    else if (!is_packet_client_generated && local_state == PACKET_RECEIVED)
    {
        assert(is_returned_error_code_correct(pkt, FRAME_ENCODING_ERROR));
    }
}

void is_new_connection_id_length_correct_client(Packet *pkt, bool is_packet_client_generated)
{
    if (!is_packet_client_generated && local_state == INITIAL)
    {
        Frame *frame = pkt->enabled_frame;
        if (frame->frame_type == NEW_CONID_FRAME)
        {
            kleener_make_symbolic(&frame->body->new_connection_id->length, 
            sizeof(frame->body->new_connection_id->length), "new_connection_id_length");

            klee_assume((frame->body->new_connection_id->length < 1) OR
                        (frame->body->new_connection_id->length > 20));

            local_state = PACKET_RECEIVED;   
        }
    }
    else if (is_packet_client_generated && local_state == PACKET_RECEIVED)
    {
        assert(is_returned_error_code_correct(pkt, FRAME_ENCODING_ERROR));
    }
}

bool new_connection_id_length_enabling_predicate(quic_state state)
{
    return (state.frame_type == NEW_CONID_FRAME);
}