#include "klee/Protocols/dtls/dtls_monitors.h"
#include "klee/Protocols/dtls/dtls_records.h"
#include "klee/klee.h"
#include <assert.h>


#define INITIAL 0
#define RECORD_RECEIVED 1
#define EXIT 2

static STATE local_state = INITIAL;
static char response[200] = "";
static bool is_input = true;

void epoch_diff_testing_server(RECORD *P, bool is_record_client_generated)
{
    if (is_record_client_generated && local_state == INITIAL) 
    {
        if (byte_to_int(P->epoch, sizeof(P->epoch)) == 0) 
        {
            determine_record_content(P, response, is_input);
            kleener_make_symbolic(&P->epoch, sizeof(P->epoch), "epoch");
            local_state = RECORD_RECEIVED;   
        }
    }
    else if (!is_record_client_generated && local_state == RECORD_RECEIVED) 
    {
        determine_record_content(P, response, !is_input);
        kleener_report_response(__FILE__, __LINE__, response, "resp");
    }
    else if (local_state == EXIT)
    {
        return;
    }
}
