#include "klee/Protocols/dtls/dtls_monitors.h"
#include "klee/Protocols/dtls/dtls_records.h"
#include "klee/Support/Protocols/helper.h"
#include "klee/klee.h"
#include <assert.h>

/* Reassembly Requirement (DTLS 1.2 RFC Section 4.2.3):
When a DTLS implementation receives a handshake message fragment, 
it MUST buffer it until it has the entire message.
*/

/*
* We capture this requirement with the aid of fragment_offset, fragment_length,
* and handshake_length. We define a symbolic byte that its offset can range up to
* handshake_length. If the fragmentation is done correctly, this symbolic offset 
* should be either (frag1_offset <= byte < frag1_offset + frag1_length) or it should 
* be (frag2_offset <= byte < frag2_offset + frag2_length)
*/

/* Discard Requirement (DTLS 1.2 RFC Section 4.1.2.7):
In general, invalid records SHOULD be silently discarded, 
thus preserving the association; however, an error MAY be 
logged for diagnostic purposes.
*/

#define INITIAL 0
#define FIRST_FRAGMENT_RECEIVED 1
#define SECOND_FRAGMENT_RECEIVED 2


static STATE local_state = INITIAL;

static uint8_t fragment_offset_f1[FRAGMENT_OFFSET_LENGTH];
static uint8_t fragment_offset_f2[FRAGMENT_OFFSET_LENGTH];
static uint8_t fragment_length_f1[FRAGMENT_LENGTH_LENGTH];
static uint8_t fragment_length_f2[FRAGMENT_LENGTH_LENGTH];
static uint32_t byte;


static bool is_reassembly_done_correctly(uint8_t *frag1_offset, uint8_t *frag1_length, uint8_t *frag2_offset, uint8_t *frag2_length, uint32_t *byte)
{
    return (
        ((byte_to_int(frag1_offset, FRAGMENT_OFFSET_LENGTH) <= *byte) & 
        (*byte < byte_to_int(frag1_offset, FRAGMENT_OFFSET_LENGTH) + byte_to_int(frag1_length, FRAGMENT_LENGTH_LENGTH)))
        |
        ((byte_to_int(frag2_offset, FRAGMENT_OFFSET_LENGTH) <= *byte) & 
        (*byte < byte_to_int(frag2_offset, FRAGMENT_OFFSET_LENGTH) + byte_to_int(frag2_length, FRAGMENT_LENGTH_LENGTH)))
    );
}

void is_fragment_reassembly_valid_server(RECORD *record, bool is_record_client_generated)
{
    if (is_record_client_generated && local_state == INITIAL)
    {
        // Make the fragment offset of the first received fragment symbolic
        kleener_make_symbolic(fragment_offset_f1, sizeof(fragment_offset_f1), "fragment_offset:f1");
        memcpy(record->RES.fragment->fragment_offset, fragment_offset_f1, sizeof(fragment_offset_f1));

        // Make the fragment length of the first received fragment symbolic
        kleener_make_symbolic(fragment_length_f1, sizeof(fragment_length_f1), "fragment_length:f1");
        memcpy(record->RES.fragment->fragment_length, fragment_length_f1, sizeof(fragment_length_f1));

        // We define a symbolic variable byte that can range from 0 to the handshake length of the received record
        uint32_t handshake_length_f1 = byte_to_int(record->RES.fragment->handshake_length, HANDSHAKE_LENGTH_LENGTH);
        byte = klee_range(0, handshake_length_f1, "byte");
        local_state = FIRST_FRAGMENT_RECEIVED;
    }
    else if (is_record_client_generated && local_state == FIRST_FRAGMENT_RECEIVED)
    {
        //  Make the fragment offset of the second fragment symbolic
        kleener_make_symbolic(fragment_offset_f2, sizeof(fragment_offset_f2), "fragment_offset:f2");
        memcpy(record->RES.fragment->fragment_offset, fragment_offset_f2, sizeof(fragment_offset_f2));

        // Make the fragment length of the second fragment symbolic
        kleener_make_symbolic(fragment_length_f2, sizeof(fragment_length_f2), "fragment_length:f2");
        memcpy(record->RES.fragment->fragment_length, fragment_length_f2, sizeof(fragment_length_f2));

        // We assume that byte is not included in any of these received fragments
        klee_assume(!(is_reassembly_done_correctly(fragment_offset_f1, fragment_length_f1, fragment_offset_f2, fragment_length_f2, &byte)));
        local_state = SECOND_FRAGMENT_RECEIVED;
    }
    else if (!is_record_client_generated && local_state == SECOND_FRAGMENT_RECEIVED)
    {
        if (record->content_type != Alert_REC)
            assert(0 && "Invalid reassembly!");
    }
}

void is_fragment_reassembly_valid_client(RECORD *record, bool is_record_client_generated)
{
    if (!is_record_client_generated && local_state == INITIAL)
    {
        kleener_make_symbolic(fragment_offset_f1, sizeof(fragment_offset_f1), "fragment_offset:f1");
        memcpy(record->RES.fragment->fragment_offset, fragment_offset_f1, sizeof(fragment_offset_f1));

        kleener_make_symbolic(fragment_length_f1, sizeof(fragment_length_f1), "fragment_length:f1");
        memcpy(record->RES.fragment->fragment_length, fragment_length_f1, sizeof(fragment_length_f1));

        uint32_t handshake_length_f1 = byte_to_int(record->RES.fragment->handshake_length, HANDSHAKE_LENGTH_LENGTH);
        byte = klee_range(0, handshake_length_f1, "byte");
        local_state = FIRST_FRAGMENT_RECEIVED;
    }
    else if (!is_record_client_generated && local_state == FIRST_FRAGMENT_RECEIVED)
    {
        kleener_make_symbolic(fragment_offset_f2, sizeof(fragment_offset_f2), "fragment_offset:f2");
        memcpy(record->RES.fragment->fragment_offset, fragment_offset_f2, sizeof(fragment_offset_f2));

        kleener_make_symbolic(fragment_length_f2, sizeof(fragment_length_f2), "fragment_length:f2");
        memcpy(record->RES.fragment->fragment_length, fragment_length_f2, sizeof(fragment_length_f2));

        klee_assume(!(is_reassembly_done_correctly(fragment_offset_f1, fragment_length_f1, fragment_offset_f2, fragment_length_f2, &byte)));
        local_state = SECOND_FRAGMENT_RECEIVED;
    }
    else if (is_record_client_generated && local_state == SECOND_FRAGMENT_RECEIVED)
    {
        if (record->content_type != Alert_REC)
            assert(0 && "Invalid reassembly!");
    }
}