#include "klee/Protocols/dtls/dtls_monitors.h"
#include "klee/Protocols/dtls/dtls_records.h"
#include "klee/klee.h"
#include <assert.h>


#define INITIAL 0
#define RECORD_RECEIVED 1
#define EXIT 2

static STATE local_state = INITIAL;

void record_sequence_number_diff_testing_server(RECORD *P, bool is_record_client_generated)
{
    if (is_record_client_generated && local_state == INITIAL) 
    {
        kleener_make_symbolic(&P->sequence_number, sizeof(P->sequence_number), "sequencenumber");
        local_state = RECORD_RECEIVED;
    }
    else if (!is_record_client_generated && local_state == RECORD_RECEIVED) 
    {
        generate_dtls_output(P);
        local_state = EXIT;
        
    }
    else if (local_state == EXIT)
    {
        return;
    }
}
