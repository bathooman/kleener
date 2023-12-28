#include "klee/Protocols/dtls/dtls_monitors.h"
#include "klee/Protocols/dtls/dtls_records.h"
#include "klee/klee.h"
#include <assert.h>

/* Requirement(DTLS 1.2 RFC 6347 Section 1):
DTLS 1.0 [DTLS1] was originally defined as a delta from [TLS11].
This document introduces a new version of DTLS, DTLS 1.2, which is
defined as a series of deltas to TLS 1.2 [TLS12].  There is no DTLS
1.1; that version number was skipped in order to harmonize version
numbers with TLS.  This version also clarifies some confusing points
in the DTLS 1.0 specification.
*/

/* Discard Requirement (DTLS 1.2 RFC Section 4.1.2.7):
In general, invalid records SHOULD be silently discarded, 
thus preserving the association; however, an error MAY be 
logged for diagnostic purposes.
*/

#define DTLS10_VERSION 0xfeff
#define DTLS12_VERSION 0xfefd

#define INITIAL 0
#define RECORD_RECEIVED 1

static STATE local_state = INITIAL;

void is_record_version_valid_server(RECORD *record, bool is_record_client_generated)
{
    if (is_record_client_generated && local_state == INITIAL)
    {   
        // We only check this requirement for records for which the epoch is zero
        // This indirectly ensures that the content of the message is not encrypted 
        if (byte_to_int(record->epoch, EPOCH_LENGTH) == 0)
        {
            // Record version is made symbolic and assumed to be invalid with respect to the valid values
            // defined for the record version
            kleener_make_symbolic(record->record_version, sizeof(record->record_version), "record_version");
            klee_assume(!(
                ((byte_to_int(record->record_version, RECORD_VERSION_LENGTH) == DTLS10_VERSION)) |
                ((byte_to_int(record->record_version, RECORD_VERSION_LENGTH) == DTLS12_VERSION))
                ));

            local_state = RECORD_RECEIVED;
        }
        
    }
    else if (!is_record_client_generated && local_state == RECORD_RECEIVED)
    {
        // The assertion is failed if one side generates a response other than an alert to an invalid input 
        if (record->content_type != Alert_REC)
            assert(0 && "invalid record version");
    }
}

void is_record_version_valid_client(RECORD *record, bool is_record_client_generated)
{    
    if (!is_record_client_generated && local_state == INITIAL)
    {
        if (byte_to_int(record->epoch, EPOCH_LENGTH) == 0)
        {
            kleener_make_symbolic(record->record_version, sizeof(record->record_version), "record_version");
            klee_assume(!(
                ((byte_to_int(record->record_version, RECORD_VERSION_LENGTH) == DTLS10_VERSION)) |
                ((byte_to_int(record->record_version, RECORD_VERSION_LENGTH) == DTLS12_VERSION))
                ));

            local_state = RECORD_RECEIVED;
        }
        
    }
    else if (is_record_client_generated && local_state == RECORD_RECEIVED)
    {
        if (record->content_type != Alert_REC)
            assert(0 && "invalid record version");
    }
}