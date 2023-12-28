#include "klee/Protocols/dtls/dtls_monitors.h"
#include "klee/Protocols/dtls/dtls_records.h"
#include "klee/klee.h"
#include <assert.h>

/* Requirement: DTLS 1.2 RFC Section 4.1
*  Equivalent to the type field in a TLS 1.2 record.
*/

/* Requirement: TLS 1.2 RFC Section 6.2.1
    enum {
          change_cipher_spec(20), alert(21), handshake(22),
          application_data(23)
      } ContentType;
*/

/* Discard Requirement (DTLS 1.2 RFC Section 4.1.2.7):
In general, invalid records SHOULD be silently discarded, 
thus preserving the association; however, an error MAY be 
logged for diagnostic purposes.
*/

/*
* For checking the validity of each type field, We have two choices:
* 1- Making sure that the type is one of the values specified by the RFC.
* 2- Use the concrete value of type in each received record to ensure the validity
* As the latter is stronger than the former, we choose the second option.
* Since we keep track of the protocol interaction and we successfully parsed the 
* received datagram into RECORD data structures, it is safe to assume that the 
* concrete value for each type field in the RECORD structure is valid.
*/

#define INITIAL 0
#define RECORD_RECEIVED 1
#define EXIT 2

static STATE local_state = INITIAL;


void is_content_type_valid_server(RECORD *P, bool is_record_client_generated)
{
    // We only check this requirement for records for which the epoch is zero
    // This indirectly ensures that the content of the message is not encrypted 
    if (is_record_client_generated && local_state == INITIAL && byte_to_int(P->epoch, sizeof(P->epoch)) == 0)
    {        
        // We store the concrete value of the content type as the valid value 
        uint8_t valid_content_type = P->content_type;

        // We make the content type symbolic and assume it to be invalid
        kleener_make_symbolic(&P->content_type, sizeof(P->content_type), "content-type");
        klee_assume(P->content_type != valid_content_type);
        local_state = RECORD_RECEIVED;
    }
    else if (!is_record_client_generated && local_state == RECORD_RECEIVED)
    {
        if (P->content_type != Alert_REC)
            assert(0 && "Invalid handshake type");
        local_state = EXIT;
    }
    else if (is_record_client_generated && local_state == RECORD_RECEIVED)
    {
        local_state = EXIT;
    }
    else if (local_state == EXIT)
    {
        return;
    }
}

void is_content_type_valid_client(RECORD *record, bool is_record_client_generated)
{
    if (!is_record_client_generated && local_state == INITIAL && byte_to_int(record->epoch, sizeof(record->epoch)) == 0)
    {
        uint8_t valid_content_type = record->content_type;
        kleener_make_symbolic(&record->content_type, sizeof(record->content_type), "content-type");
        klee_assume(record->content_type != valid_content_type);
        local_state = RECORD_RECEIVED;
    }
    else if (is_record_client_generated && local_state == RECORD_RECEIVED)
    {
        if (record->content_type != Alert_REC)
            assert(0 && "Invalid handshake type");
        local_state = EXIT;
    }
    else if (!is_record_client_generated && local_state == RECORD_RECEIVED)
    {
        local_state = EXIT;
    }
    else if (local_state == EXIT)
    {
        return;
    }
}