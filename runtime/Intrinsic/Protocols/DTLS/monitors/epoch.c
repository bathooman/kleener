#include "klee/Protocols/dtls/dtls_monitors.h"
#include "klee/Protocols/dtls/dtls_records.h"
#include "klee/klee.h"
#include <assert.h>

/* Epoch Requirement (DTLS 1.2 RFC Section 4.1):
The epoch number is initially zero and is
incremented each time a ChangeCipherSpec message is sent
*/


/* Discard Requirement (DTLS 1.2 RFC Section 4.1.2.7):
In general, invalid records SHOULD be silently discarded, 
thus preserving the association; however, an error MAY be 
logged for diagnostic purposes.
*/


#define INITIAL 0
#define RECORD_RECEIVED 1
static size_t ccs_counter = 0;

static STATE local_state = INITIAL;

void is_epoch_valid_server(RECORD *record, bool is_record_client_generated)
{
    /*
    * The valid value for epoch is equal to zero and
    * each time a CCS is sent, the valid value for epoch 
    * should be incremented
    */
    if (is_record_client_generated && local_state == INITIAL)
    {
        // We only check this requirement for records for which the epoch is zero
        // This indirectly ensures that the content of the message is not encrypted 
        if (byte_to_int(record->epoch, sizeof(record->epoch)) == 0)
        {
            // We make the epoch symbolic and assume it to be invalid
            kleener_make_symbolic(record->epoch, sizeof(record->epoch), "epoch");
            klee_assume(byte_to_int(record->epoch, sizeof(record->epoch)) != ccs_counter);
            local_state = RECORD_RECEIVED;
        }        
    }
    else if (is_record_client_generated && record->content_type == Change_Cipher_Spec_REC)
    {
        // The valid value for epoch is incremented in the case a CCS is sent
        ccs_counter += 1;
    }
    else if (!is_record_client_generated && local_state == RECORD_RECEIVED)
    {
        // Assert(0) if server generates a response despite receiving invalid epoch
        if (record->content_type != Alert_REC)
            assert(0 && "invalid epoch");
    }
   
}

void is_epoch_valid_client(RECORD *record, bool is_record_client_generated)
{
    if (!is_record_client_generated && local_state == INITIAL)
    {
        if (byte_to_int(record->epoch, sizeof(record->epoch)) == 0)
        {
            kleener_make_symbolic(record->epoch, sizeof(record->epoch), "epoch");
            klee_assume(byte_to_int(record->epoch, sizeof(record->epoch)) != ccs_counter);
            local_state = RECORD_RECEIVED;
        }
        
    }
    else if (!is_record_client_generated && record->content_type == Change_Cipher_Spec_REC)
    {
        ccs_counter = ccs_counter + 1;
    }
    else if (is_record_client_generated && local_state == RECORD_RECEIVED)
    {
        if (record->content_type != Alert_REC)
            assert(0 && "invalid epoch");
    }
}