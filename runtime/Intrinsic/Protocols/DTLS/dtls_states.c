#include "klee/Protocols/dtls/dtls_records.h"
#include "klee/Protocols/dtls/dtls_states.h"
#include "klee/Support/Protocols/helper.h"
#include "klee/klee.h"
#include <assert.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdbool.h>


#define OR |
#define AND &


int state_to_message_type(int state)
{
	switch (state)
	{
	case CH0_RECVD | CH2_RECVD:
		return Client_Hello_MSG;
		break;

	case CKE_RECVD:
		return Client_Key_Exchange_MSG;
		break;
		
	
	case HVR_RECVD:
		return Hello_Verify_Request_MSG;
		break;

	case SH_RECVD:
		return Server_Hello_MSG;
		break;

	case SHD_RECVD:
		return Server_Hello_Done_MSG;
		break;

	default:
		break;
	}
	return -1;
}

void DTLS_server_state_machine(RECORD *record, RECORD *shadow_record, size_t counter, int8_t *server_current_state)
{
	RECORD *shadow_rec = shadow_record + counter;

	if (shadow_rec->content_type == Handshake_REC)
	{

		if (byte_to_int((shadow_rec->epoch), 2) == 0)
		{
			switch (shadow_rec->RES.fragment->handshake_type)
			{
			case Client_Hello_MSG:
				if (shadow_rec->RES.fragment->body.client_hello->cookie_length == 0)
					*server_current_state = CH0_RECVD;
				else
					*server_current_state = CH2_RECVD;

				printf("\n[Server-model-log] client_hello has been parsed\n");
				break;
			
			case Certificate_MSG:

				*server_current_state = CCE_RECVD;
				printf("\n[Server-model-log] Certificate has been parsed\n");
				break;
			
			case Client_Key_Exchange_MSG:

				*server_current_state = CKE_RECVD;
				printf("\n[Server-model-log] client_key_exchange has been parsed\n");
				break;
			
			case Certificate_Verify_MSG:

				*server_current_state = CEV_RECVD;
				printf("\n[Server-model-log] Certificate_verify has been parsed\n");
				break;
			
			default:
				printf("[Server-model-log] Unknown Message has been received!!\n");
				break;
			}
		}
		else
		{
			*server_current_state = CFI_RECVD;
			printf("\n[Server-model-log] finished has been parsed\n");
		}
	}
	else if (shadow_rec->content_type == Change_Cipher_Spec_REC)
	{
		*server_current_state = CCC_RECVD;
		printf("\n[Server-model-log] change_cipher_spec has been parsed\n");
	}
	else if (shadow_rec->content_type == Application_Data)
	{
		*server_current_state = CAPP_RECVD;
		printf("\n[Server-model-log] Application Data has been parsed\n");
	}
	else if (shadow_rec->content_type == Alert_REC)
	{
		*server_current_state = CALRT_RCVD;
		printf("\n[Server-model-log] Alert has been parsed\n");
	}
	else if (shadow_rec->content_type == Heartbeat_REC)
	{
		printf("\n[Server-model-log] Heartbeat has been parsed\n");
	}
	
}
void DTLS_client_state_machine(RECORD *record, RECORD *shadow_record, size_t counter, int8_t *client_current_state)
{
	RECORD *shadow_rec = shadow_record + counter;

	if (shadow_rec->content_type == Handshake_REC)
	{
		if (byte_to_int((shadow_rec->epoch), 2) == 0)
		{
			switch (shadow_rec->RES.fragment->handshake_type)
			{
			case Hello_Verify_Request_MSG:
				*client_current_state = HVR_RECVD;
				printf("\n[Client-model-log] Hello Verify Request has been parsed\n");
				break;
			
			case Server_Hello_MSG:
				*client_current_state = SH_RECVD;
				printf("\n[Client-model-log] Server Hello has been parsed\n");
				break;

			case Certificate_MSG:
				*client_current_state = SCE_RECVD;
				printf("\n[Client-model-log] Server Certificate has been parsed\n");
				break;

			case Server_Key_Exchange_MSG:
				*client_current_state = SKE_RECVD;
				printf("\n[Client-model-log] Server Key Exchange has been parsed\n");
				break;

			case Certificate_Request_MSG:
				*client_current_state = CER_RECVD;
				printf("\n[Client-model-log] Certificate Request has been parsed\n");
				break;

			case Server_Hello_Done_MSG:
				*client_current_state = SHD_RECVD;
				printf("\n[Client-model-log] Server Hello Done has been parsed\n");
				break;

			default:
				break;
			}
		}
		else
		{
			*client_current_state = SFI_RECVD;
			printf("\n[Client-model-log] finished has been parsed\n");
		}
	}
	else if (shadow_rec->content_type == Change_Cipher_Spec_REC)
	{
		*client_current_state = SCC_RECVD;
		printf("\n[Client-model-log] change_cipher_spec has been parsed\n");
	}
	else if (shadow_rec->content_type == Application_Data)
	{
		*client_current_state = SAPP_RECVD;
		printf("\n[Client-model-log] Application Data has been parsed\n");
	}
	else if (shadow_rec->content_type == Alert_REC)
	{
		*client_current_state = SALRT_RCVD;
		printf("\n[Client-model-log] Alert has been parsed\n");
	}
	else if (shadow_rec->content_type == Heartbeat_REC)
	{
		printf("\n[Client-model-log] Heartbeat has been parsed\n");
	}
}