#ifndef SYM_STATE
#define SYM_STATE

#include <stdint.h>
#include <stdbool.h>
#include "klee/Protocols/dtls/dtls_records.h"


#define INIT -1
#define CH0_RECVD 0
#define CH2_RECVD 2
#define CCE_RECVD 8
#define CKE_RECVD 9
#define CEV_RECVD 10
#define CCC_RECVD 11
#define CFI_RECVD 12
#define CAPP_RECVD 15

#define HVR_RECVD 1
#define SH_RECVD 3
#define SCE_RECVD 4
#define SKE_RECVD 5
#define CER_RECVD 6 
#define SHD_RECVD 7
#define SCC_RECVD 13
#define SFI_RECVD 14
#define SAPP_RECVD 16
#define ALRT_DECRYPT_ERR 20

int state_to_message_type(int state);
void DTLS_server_state_machine(RECORD *rec, RECORD *shadow_record, size_t counter, int8_t *server_current_state);
void DTLS_client_state_machine(RECORD *rec, RECORD *shadow_record, size_t counter, int8_t *client_current_state);

#endif