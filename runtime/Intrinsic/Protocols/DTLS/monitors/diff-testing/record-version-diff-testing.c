#include "klee/Protocols/dtls/dtls_monitors.h"
#include "klee/Protocols/dtls/dtls_records.h"
#include "klee/klee.h"
#include <assert.h>


#define INITIAL 0
#define RECORD_RECEIVED 1
#define EXIT 2

static STATE local_state = INITIAL;

void record_version_diff_testing_server(RECORD *P, bool is_record_client_generated)
{
    if (is_record_client_generated && local_state == INITIAL) 
    {
        kleener_make_symbolic(&P->record_version, sizeof(P->record_version), "recordversion");
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
