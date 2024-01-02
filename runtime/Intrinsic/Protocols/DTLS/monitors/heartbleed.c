#include "klee/Protocols/dtls/dtls_monitors.h"
#include "klee/Protocols/dtls/dtls_records.h"
#include "klee/klee.h"
#include <assert.h>

#define INITIAL 0
#define RECORD_RECEIVED 1

#define HEARTBEAT_REQUEST 1
#define HEARTBEAT_RESPONSE 2

/* RFC6520 Section 3
enum {
      heartbeat_request(1),
      heartbeat_response(2),
      (255)
} HeartbeatMessageType;
*/

/* RFC6520 Section 3
 * However, a HeartbeatRequest message SHOULD NOT be sent during handshakes.
 */

/* RFC6520 Section 4
When a HeartbeatRequest message is received and sending a
HeartbeatResponse is not prohibited as described elsewhere in this
document, the receiver MUST send a corresponding HeartbeatResponse
message carrying an exact copy of the payload of the received
HeartbeatRequest.
*/

/* Discard Requirement (DTLS 1.2 RFC Section 4.1.2.7):
In general, invalid records SHOULD be silently discarded, 
thus preserving the association; however, an error MAY be 
logged for diagnostic purposes.
*/

static STATE local_state = INITIAL;
static uint8_t request_payload_length[2];
static uint16_t concrete_request_payload_length;

void check_heartbleed_server(RECORD *record, bool is_record_client_generated) 
{
  if (is_record_client_generated && local_state == INITIAL) 
  {
    if (record->content_type == Heartbeat_REC) 
    {
      if (record->RES.heartbeat.type == HEARTBEAT_REQUEST) {
        concrete_request_payload_length = byte_to_int(record->RES.heartbeat.payload_length, sizeof(record->RES.heartbeat.payload_length));
        klee_make_symbolic(request_payload_length, sizeof(request_payload_length), "request_payload_length");
        klee_assume(byte_to_int(request_payload_length, sizeof(request_payload_length)) != concrete_request_payload_length);
        memcpy(record->RES.heartbeat.payload_length, request_payload_length, sizeof(request_payload_length));
        local_state = RECORD_RECEIVED;
      }
    }
  }
  else if (!is_record_client_generated && local_state == RECORD_RECEIVED) 
  {
    if (record->content_type == Heartbeat_REC)
    {
        if (record->RES.heartbeat.type == HEARTBEAT_RESPONSE)
        {
            // The assertion is failed if one side generates a response other than an alert to an invalid input 
            if (record->content_type != Alert_REC)
                assert(0 && "invalid payload length");
        }
    }
  }
}