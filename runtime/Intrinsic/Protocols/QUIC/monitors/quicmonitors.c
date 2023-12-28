#include "klee/Protocols/quic/quic_monitors.h"
#include "klee/Support/Protocols/helper.h"
#include "klee/klee.h"

quic_monitor_handle set_quic_monitor_handle(int experiment, SIDE side_to_check)
{
    static const struct entry {quic_monitor_handle server_mon; quic_monitor_handle client_mon;} table[] = 
    {
        [quic_normal_execution] = {NULL, NULL},
        [initial_token_length_requirement] = {NULL, is_initial_token_length_valid_client},
        [version_negotiation_requirement] = {is_version_negotiation_done_correctly_server, NULL},
        [reserved_bits_requirement] = {are_reserved_bits_correct_server, are_reserved_bits_correct_client},
        [fixed_bit_requirement] = {is_fixed_bit_correct_server, is_fixed_bit_correct_client},
        [dst_connection_id_length_requirement] = {is_dest_id_length_correct_server, is_dest_id_length_correct_client},
        [src_connection_id_length_requirement] = {is_src_id_length_correct_server, is_src_id_length_correct_client},
        [inconsistent_versions_requirement] = {are_inconsistent_versions_handled_correctly, NULL},
        [frame_type_requirement] = {is_frame_type_valid_server, is_frame_type_valid_client},
        [packet_length_requirement] = {is_packet_length_correct_server, is_packet_length_correct_client},
        [ack_ranges_requirement] = {is_ack_range_valid_server, is_ack_range_valid_client},
        [empty_token_requirement] = {NULL, is_empty_token_handled_correctly_client},
        [client_new_token_requirement] = {is_client_generated_new_token_handled_correctly, NULL},
        [new_connection_id_length_requirement] = {is_new_connection_id_length_correct_server, is_new_connection_id_length_correct_client},
        [retire_prior_to_requirement] = {is_retire_less_equal_to_sequence_number_server, is_retire_less_equal_to_sequence_number_client},
        [handshake_done_receipt_requirement] = {is_client_generated_handshake_done_handled_correctly, NULL},
        [stream_size_requirement] = {is_oversized_stream_handled_correctly_server, is_oversized_stream_handled_correctly_client},
        [new_token_length_requirement] = {is_new_token_length_correct_server, is_new_token_length_correct_client},
        [crypto_length_requirement] = {is_crypto_length_correct_server, is_crypto_length_correct_client}

    };
    const struct entry *entry = &table[experiment];

	if (side_to_check == CLIENT)
		return entry->client_mon;
	else if (side_to_check == SERVER)
		return entry->server_mon;
	else 
		return NULL;
}

quic_enabling_predicate set_quic_enabling_predicate(int experiment)
{
    static const struct entry {quic_enabling_predicate pred;} table[] = 
    {
        [quic_normal_execution] = {NULL},
        [initial_token_length_requirement] = {initial_token_length_enabling_predicate},
        [version_negotiation_requirement] = {version_negotation_enabling_predicate}, 
        [reserved_bits_requirement] = {reserved_bits_enabling_predicate},
        [fixed_bit_requirement] = {fixed_bit_enabling_predicate},
        [dst_connection_id_length_requirement] = {dest_id_length_enabling_predicate},
        [src_connection_id_length_requirement] = {src_id_length_enabling_predicate},
        [inconsistent_versions_requirement] = {inconsistent_versions_enabling_predicate},
        [packet_length_requirement] = {packet_length_enabling_predicate},
        [frame_type_requirement] = {frame_type_enabling_predicate},
        [ack_ranges_requirement] = {ack_range_enabling_predicate},
        [empty_token_requirement] = {empty_token_enabling_predicate},
        [client_new_token_requirement] = {client_generated_new_token_enabling_predicate},
        [new_connection_id_length_requirement] = {new_connection_id_length_enabling_predicate},
        [retire_prior_to_requirement] = {retire_less_equal_to_sequence_number_enabling_predicate},
        [handshake_done_receipt_requirement] = {client_generated_handshake_done_enabling_predicate},
        [stream_size_requirement] = {oversized_stream_enabling_predicate},
        [new_token_length_requirement] = {new_token_length_enabling_predicate},
        [crypto_length_requirement] = {crypto_length_enabling_predicate}

    };
    const struct entry *entry = &table[experiment];

	return entry->pred;
}

quic_state determine_quic_state_to_check(quic_enabling_predicate pred, SIDE side_to_check)
{   
    quic_state ret_pred;
    if (side_to_check == NONE)
    {
        ret_pred.frame_index = INIT;
        ret_pred.frame_type = INIT;
        ret_pred.packet_type = INIT;
        ret_pred.packet_number = INIT;
    }
    else
    {
        int8_t frame_index;
        int8_t frame_type;
        int8_t packet_type;
        int64_t packet_number;
        klee_make_symbolic(&frame_index, sizeof(frame_index), "state_to_check-frame_index");
        ret_pred.frame_index = frame_index;
        klee_make_symbolic(&frame_type, sizeof(frame_type), "state_to_check-frame_type");
        ret_pred.frame_type = frame_type;
        klee_make_symbolic(&packet_type, sizeof(packet_type), "state_to_check-packet_type");
        ret_pred.packet_type = packet_type;
        klee_make_symbolic(&packet_number, sizeof(packet_number), "state_to_check-packet_number");
        ret_pred.packet_number = packet_number;
        klee_assume(pred(ret_pred));        
    }

    return ret_pred;
}

bool is_packet_level_monitor(const char *level_env)
{
    if (strcmp(level_env, "packet") == 0)
    {
        return 1;
    }
    else if (strcmp(level_env, "frame") == 0)
    {
        return 0;
    }        
    else
    {
        printf("\n[Model-log] Environment Variable MONITOR_LEVEL is Invalid\n");
        exit(-1);
    }
        
}