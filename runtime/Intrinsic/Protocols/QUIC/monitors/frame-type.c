#include "klee/Protocols/quic/quic_packets.h"
#include "klee/Protocols/quic/quic_states.h"
#include "klee/Support/Protocols/helper.h"
#include "klee/klee.h"

#include <assert.h>

/* Section 12.4
* Table 3 lists and summarizes information about each frame type that
   is defined in this specification.  A description of this summary is
   included after the table.

    +============+======================+===============+======+======+
    | Type Value | Frame Type Name      | Definition    | Pkts | Spec |
    +============+======================+===============+======+======+
    | 0x00       | PADDING              | Section 19.1  | IH01 | NP   |
    +------------+----------------------+---------------+------+------+
    | 0x01       | PING                 | Section 19.2  | IH01 |      |
    +------------+----------------------+---------------+------+------+
    | 0x02-0x03  | ACK                  | Section 19.3  | IH_1 | NC   |
    +------------+----------------------+---------------+------+------+
    | 0x04       | RESET_STREAM         | Section 19.4  | __01 |      |
    +------------+----------------------+---------------+------+------+
    | 0x05       | STOP_SENDING         | Section 19.5  | __01 |      |
    +------------+----------------------+---------------+------+------+
    | 0x06       | CRYPTO               | Section 19.6  | IH_1 |      |
    +------------+----------------------+---------------+------+------+
    | 0x07       | NEW_TOKEN            | Section 19.7  | ___1 |      |
    +------------+----------------------+---------------+------+------+
    | 0x08-0x0f  | STREAM               | Section 19.8  | __01 | F    |
    +------------+----------------------+---------------+------+------+
    | 0x10       | MAX_DATA             | Section 19.9  | __01 |      |
    +------------+----------------------+---------------+------+------+
    | 0x11       | MAX_STREAM_DATA      | Section 19.10 | __01 |      |
    +------------+----------------------+---------------+------+------+
    | 0x12-0x13  | MAX_STREAMS          | Section 19.11 | __01 |      |
    +------------+----------------------+---------------+------+------+
    | 0x14       | DATA_BLOCKED         | Section 19.12 | __01 |      |
    +------------+----------------------+---------------+------+------+
    | 0x15       | STREAM_DATA_BLOCKED  | Section 19.13 | __01 |      |
    +------------+----------------------+---------------+------+------+
    | 0x16-0x17  | STREAMS_BLOCKED      | Section 19.14 | __01 |      |
    +------------+----------------------+---------------+------+------+
    | 0x18       | NEW_CONNECTION_ID    | Section 19.15 | __01 | P    |
    +------------+----------------------+---------------+------+------+
    | 0x19       | RETIRE_CONNECTION_ID | Section 19.16 | __01 |      |
    +------------+----------------------+---------------+------+------+
    | 0x1a       | PATH_CHALLENGE       | Section 19.17 | __01 | P    |
    +------------+----------------------+---------------+------+------+
    | 0x1b       | PATH_RESPONSE        | Section 19.18 | ___1 | P    |
    +------------+----------------------+---------------+------+------+
    | 0x1c-0x1d  | CONNECTION_CLOSE     | Section 19.19 | ih01 | N    |
    +------------+----------------------+---------------+------+------+
    | 0x1e       | HANDSHAKE_DONE       | Section 19.20 | ___1 |      |
    +------------+----------------------+---------------+------+------+

* An endpoint MUST treat the receipt of a frame of unknown type as a
* connection error of type FRAME_ENCODING_ERROR.
*/

/* RFC9221: Section 4
* DATAGRAM frames are used to transmit application data in an unreliable manner. 
* The Type field in the DATAGRAM frame takes the form 0b0011000X (or the values 0x30 and 0x31).
*/

#define INITIAL 0
#define PACKET_RECEIVED 1

static STATE local_state = INITIAL;

void is_frame_type_valid_server(Packet *pkt, bool is_packet_client_generated)
{
    if (is_packet_client_generated && local_state == INITIAL)
    {
        Frame *frame = pkt->enabled_frame;
        if (frame != NULL)
        {
            char symbolic_name[20];
            uint8_t pn_size = decode_packet_number_length(&pkt->base);
            uint8_t packet_number = byte_to_int(pkt->packet_number, pn_size);
            uint8_t frame_type_concrete_value = frame->frame_type;
            sprintf(symbolic_name, "%s:%d", "frame_type_PN", packet_number);

            kleener_make_symbolic(&frame->frame_type, sizeof(frame->frame_type), symbolic_name);
            klee_assume((frame->frame_type & 0b11000000) == (frame_type_concrete_value & 0b11000000));
            klee_assume(!((frame->frame_type >= 0x0) AND (frame->frame_type <= 0x1e)));
            klee_assume(!(frame->frame_type == 0x30));
            klee_assume(!(frame->frame_type == 0x31));
            local_state = PACKET_RECEIVED;
        }
        
    }
    else if (!is_packet_client_generated && local_state == PACKET_RECEIVED)
    {
        assert(is_returned_error_code_correct(pkt, FRAME_ENCODING_ERROR));
    }
}

void is_frame_type_valid_client(Packet *pkt, bool is_packet_client_generated)
{
    if (!is_packet_client_generated && local_state == INITIAL)
    {
        Frame *frame = pkt->enabled_frame;
        if (frame != NULL)
        {
            char symbolic_name[20];
            uint8_t pn_size = decode_packet_number_length(&pkt->base);
            uint8_t packet_number = byte_to_int(pkt->packet_number, pn_size);
            uint8_t frame_type_concrete_value = frame->frame_type;
            sprintf(symbolic_name, "%s:%d", "frame_type_PN", packet_number);

            kleener_make_symbolic(&frame->frame_type, sizeof(frame->frame_type), symbolic_name);
            klee_assume((frame->frame_type & 0b11000000) == (frame_type_concrete_value & 0b11000000));
            klee_assume(!((frame->frame_type >= 0x0) AND (frame->frame_type <= 0x1e)));
            klee_assume(!(frame->frame_type == 0x30));
            klee_assume(!(frame->frame_type == 0x31));
            local_state = PACKET_RECEIVED;
        }
    }
    else if (is_packet_client_generated && local_state == PACKET_RECEIVED)
    {
        assert(is_returned_error_code_correct(pkt, FRAME_ENCODING_ERROR));
    }
}

bool frame_type_enabling_predicate(quic_state state)
{
    return 1;
}