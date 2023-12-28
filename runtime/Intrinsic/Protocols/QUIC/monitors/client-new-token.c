#include "klee/Protocols/quic/quic_packets.h"
#include "klee/Protocols/quic/quic_states.h"
#include "klee/Support/Protocols/helper.h"
#include "klee/klee.h"
#include <assert.h>

/* Section 19.7
* Clients MUST NOT send NEW_TOKEN frames. A server MUST treat receipt of a
* NEW_TOKEN frame as a connection error of type PROTOCOL_VIOLATION.
*/

#define INITIAL 0
#define PACKET_RECEIVED 1

static STATE local_state = INITIAL;

void is_client_generated_new_token_handled_correctly(Packet *pkt, bool is_packet_client_generated)
{
    if (is_packet_client_generated && local_state == INITIAL)
    {            
        Frame *frame = pkt->enabled_frame;
        if (frame != NULL)
        {
            kleener_make_symbolic(&frame->frame_type, sizeof(frame->frame_type), "frame_type");
            klee_assume(frame->frame_type == NEW_TOKEN_FRAME); 
            local_state = PACKET_RECEIVED; 
        }
        
    }
    else if (!is_packet_client_generated && local_state == PACKET_RECEIVED)
    {
        assert(is_returned_error_code_correct(pkt, PROTOCOL_VIOLATION));
    }
}

bool client_generated_new_token_enabling_predicate(quic_state state)
{
    return 1;
}
