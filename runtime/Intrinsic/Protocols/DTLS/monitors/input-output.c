#include "klee/Protocols/dtls/dtls_monitors.h"
#include "klee/Protocols/dtls/dtls_records.h"
#include "klee/Support/Protocols/helper.h"
#include "klee/klee.h"
#include <assert.h>

#define INITIAL 0
#define REC_RECEIVED 1

static STATE local_state = INITIAL;
static char response[500] = "";
static bool is_input = true;

void inp_outp_server(RECORD *record, bool is_record_client_generated) 
{
  if (is_record_client_generated && local_state == INITIAL) 
  {
    if (byte_to_int(record->epoch, sizeof(record->epoch)) == 0) 
    {
      determine_record_content(record, response, sizeof(response), is_input);
      if (record->content_type == Handshake_REC) 
      {
        if (record->RES.fragment->handshake_type == Client_Hello_MSG && record->RES.fragment->body.client_hello->cookie_length == 0) 
        {
          kleener_make_symbolic(record->record_version, sizeof(record->record_version), "record_version");
          kleener_make_symbolic(record->sequence_number, sizeof(record->sequence_number), "record_sequence_number");
          local_state = REC_RECEIVED;
        }
      }      
    }
  }
  if (!is_record_client_generated && local_state == REC_RECEIVED) {
    determine_record_content(record, response, sizeof(response), !is_input);
    kleener_report_response(__FILE__, __LINE__, response, "resp");
  }
}