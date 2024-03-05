#include "klee/Protocols/dtls/dtls_monitors.h"
#include "klee/Protocols/dtls/dtls_records.h"
#include "klee/Protocols/dtls/dtls_states.h"

#include "klee/klee.h"


monitor_handle set_monitor_handle(int experiment, SIDE side_to_check)
{   
    static const struct entry {monitor_handle server_mon; monitor_handle client_mon;} table[] = 
    {
        [epoch_requirement] = {is_epoch_valid_server, is_epoch_valid_client},
        [content_type_requirement] = {is_content_type_valid_server, is_content_type_valid_client},
        [record_version_requirement] = {is_record_version_valid_server, is_record_version_valid_client},
        [record_length_requirement] = {is_record_length_valid_server, is_record_length_valid_client},
        [record_sequence_requirement] = {is_record_sequence_number_valid_server, is_record_sequence_number_valid_client},
        [handshake_type_requirement] = {is_handshake_type_valid_server, is_handshake_type_valid_client},
        [extensions_length_requirement] = {is_extensions_length_valid_server, is_extensions_length_valid_client}, 
		[fragment_reassembly_requirement] = {is_fragment_reassembly_valid_server, is_fragment_reassembly_valid_client},
        [fragment_message_sequence_requirement] = {is_message_seq_equal_in_fragments_server, is_message_seq_equal_in_fragments_client},
		[fragment_message_length_requirement] = {is_message_length_equal_in_fragments_server, is_message_length_equal_in_fragments_client},
		[unfragmented_message_offset_requirement] = {is_unfragmented_message_offset_valid_server, is_unfragmented_message_offset_valid_client},
		[unfragmented_message_length_requirement] = {is_unfragmented_message_length_valid_server, is_unfragmented_message_length_valid_client},
		[handshake_version_requirement] = {is_handshake_version_valid_server, is_handshake_version_valid_client},
		[fragment_length_requirement] = {is_fragment_length_valid_server, is_fragment_length_valid_client},
		[cookie_length_requirement] = {is_cookie_length_valid_server, is_cookie_length_valid_client},
		[session_id_length_requirement] = {is_session_id_length_valid_server, is_session_id_length_valid_client},
		[CH0HVR_output_requirement] = {is_ch0_hvr_message_sequence_equal, NULL},
		[CH2SH_output_requirement] = {is_ch2_sh_message_sequence_equal, NULL},
        [SH_cipher_suite_supported_output_requirement] = {is_sh_cipher_suite_supported, NULL},
		[handshake_length_requirement] = {is_handshake_length_valid_server, is_handshake_length_valid_client},
		[signature_hash_algorithms_requirement] = {NULL, is_hash_sig_algorithm_equal},
		[signature_hash_length_requirement] = {NULL, is_hash_sig_algorithm_length_valid},
		[certificate_count_requirement] = {NULL, is_certificate_type_count_valid},
		[heartbleed_requirement] = {check_heartbleed_server, NULL},
		/* Differential Testing Monitors*/
		[content_type_diff_test] = {content_type_diff_testing_server, NULL},
		[epoch_diff_test] = {epoch_diff_testing_server, NULL},
		[record_sequence_number_diff_test] = {record_sequence_number_diff_testing_server, NULL}
    };
    const struct entry *entry = &table[experiment];

	if (side_to_check == CLIENT)
		return entry->client_mon;
	else if (side_to_check == SERVER)
		return entry->server_mon;
	else 
		return NULL;
}

allowed_states set_monitor_valid_states(int experiment, SIDE side_to_check)
{
    static const struct entry {allowed_states server_states; allowed_states client_states;} table[] = 
    {
        [epoch_requirement] = {RECORD_LAYER_SERVER_STATES, RECORD_LAYER_CLIENT_STATES},
        [content_type_requirement] = {RECORD_LAYER_SERVER_STATES, RECORD_LAYER_CLIENT_STATES},
        [record_version_requirement] = {RECORD_LAYER_SERVER_STATES, RECORD_LAYER_CLIENT_STATES},
        [record_length_requirement] = {RECORD_LAYER_SERVER_STATES, RECORD_LAYER_CLIENT_STATES},
        [record_sequence_requirement] = {AS_CH2_RECVD | AS_CKE_RECVD | AS_CCE_RECVD | AS_CEV_RECVD | AS_CCC_RECVD,
        RECORD_LAYER_CLIENT_STATES},
        [handshake_type_requirement] = {HANDSHAKE_LAYER_SERVER_STATES, HANDSHAKE_LAYER_CLIENT_STATES},
        [extensions_length_requirement] = {AS_CH0_RECVD | AS_CH2_RECVD, AS_SH_RECVD},
		[fragment_reassembly_requirement] = {AS_CKE_RECVD, AS_SH_RECVD},
        [fragment_message_sequence_requirement] = {AS_CKE_RECVD, AS_SH_RECVD},
		[fragment_message_length_requirement] = {AS_CKE_RECVD, AS_SH_RECVD},
		[unfragmented_message_offset_requirement] = {HANDSHAKE_LAYER_SERVER_STATES, HANDSHAKE_LAYER_CLIENT_STATES},
		[unfragmented_message_length_requirement] = {HANDSHAKE_LAYER_SERVER_STATES, HANDSHAKE_LAYER_CLIENT_STATES},
		[handshake_version_requirement] = {AS_CH0_RECVD | AS_CH2_RECVD, AS_HVR_RECVD | AS_SH_RECVD},
		[fragment_length_requirement] = {HANDSHAKE_LAYER_SERVER_STATES, HANDSHAKE_LAYER_CLIENT_STATES},
		[cookie_length_requirement] = {AS_CH0_RECVD | AS_CH2_RECVD, AS_HVR_RECVD},
		[session_id_length_requirement] = {AS_CH0_RECVD | AS_CH2_RECVD, AS_SH_RECVD},
		[CH0HVR_output_requirement] = {AS_CH0_RECVD, AS_HVR_RECVD},
		[CH2SH_output_requirement] = {AS_CH2_RECVD, AS_SH_RECVD},
        [SH_cipher_suite_supported_output_requirement] = {AS_CH2_RECVD, AS_SH_RECVD},
		[handshake_length_requirement] = {HANDSHAKE_LAYER_SERVER_STATES, HANDSHAKE_LAYER_CLIENT_STATES},
		[signature_hash_algorithms_requirement] = {AS_CEV_RECVD, AS_CER_RECVD},
		[signature_hash_length_requirement] = {AS_CEV_RECVD, AS_CER_RECVD},
		[certificate_count_requirement] = {AS_CEV_RECVD, AS_CER_RECVD},
		[heartbleed_requirement] = {AS_CFI_RECVD, AS_SFI_RECVD},
		/* Differential Testing Monitors*/
		[content_type_diff_test] = {RECORD_LAYER_SERVER_STATES, RECORD_LAYER_CLIENT_STATES},
		[epoch_diff_test] = {RECORD_LAYER_SERVER_STATES, RECORD_LAYER_CLIENT_STATES},
		[record_sequence_number_diff_test] = {RECORD_LAYER_SERVER_STATES, RECORD_LAYER_CLIENT_STATES}
    };
    const struct entry *entry = &table[experiment];

	if (side_to_check == CLIENT)
		return entry->client_states;
	else if (side_to_check == SERVER)
		return entry->server_states;
	else 
		return RECORD_LAYER_SERVER_STATES | RECORD_LAYER_CLIENT_STATES;
}




int determine_state_to_check(allowed_states as, SIDE side_to_check, bool is_cipher_ecc)
{	
	if (side_to_check == NONE)
	{
		return SFI_RECVD;
	}
	else
	{
		int state_to_check;
		kleener_make_symbolic(&state_to_check, sizeof(state_to_check), "state_to_check");
		bool condition = false;
		if (side_to_check == SERVER && !is_cipher_ecc)
		{
			if (as & AS_CH0_RECVD) condition |= (state_to_check == CH0_RECVD);
			if (as & AS_CH2_RECVD) condition |= (state_to_check == CH2_RECVD);
			if (as & AS_CKE_RECVD) condition |= (state_to_check == CKE_RECVD);
			if (as & AS_CCC_RECVD) condition |= (state_to_check == CCC_RECVD);
			if (as & AS_CFI_RECVD) condition |= (state_to_check == CFI_RECVD);
		}
		else if (side_to_check == CLIENT && !is_cipher_ecc)
		{
			if (as & AS_HVR_RECVD) condition |= (state_to_check == HVR_RECVD);
			if (as & AS_SH_RECVD) condition |= (state_to_check == SH_RECVD);
			if (as & AS_SHD_RECVD) condition |= (state_to_check == SHD_RECVD);
			if (as & AS_SCC_RECVD) condition |= (state_to_check == SCC_RECVD);
			if (as & AS_SFI_RECVD) condition |= (state_to_check == SFI_RECVD);
		}
		else if (side_to_check == SERVER && is_cipher_ecc)
		{
			if (as & AS_CH0_RECVD) condition |= (state_to_check == CH0_RECVD);
			if (as & AS_CH2_RECVD) condition |= (state_to_check == CH2_RECVD);
			if (as & AS_CCE_RECVD) condition |= (state_to_check == CCE_RECVD);
			if (as & AS_CKE_RECVD) condition |= (state_to_check == CKE_RECVD);
			if (as & AS_CEV_RECVD) condition |= (state_to_check == CEV_RECVD);
			if (as & AS_CCC_RECVD) condition |= (state_to_check == CCC_RECVD);
			if (as & AS_CFI_RECVD) condition |= (state_to_check == CFI_RECVD);
		}
		else if (side_to_check == CLIENT && is_cipher_ecc)
		{
			if (as & AS_HVR_RECVD) condition |= (state_to_check == HVR_RECVD);
			if (as & AS_SH_RECVD) condition |= (state_to_check == SH_RECVD);
			if (as & AS_SCE_RECVD) condition |= (state_to_check == SCE_RECVD);
			if (as & AS_SKE_RECVD) condition |= (state_to_check == SKE_RECVD);
			if (as & AS_CER_RECVD) condition |= (state_to_check == CER_RECVD);
			if (as & AS_SHD_RECVD) condition |= (state_to_check == SHD_RECVD);
			if (as & AS_SCC_RECVD) condition |= (state_to_check == SCC_RECVD);
			if (as & AS_SFI_RECVD) condition |= (state_to_check == SFI_RECVD);
		}

		klee_assume(condition);
		return state_to_check;
	}
	
	
}