#ifndef DTLS_MONITORS
#define DTLS_MONITORS

#include "klee/Protocols/dtls/dtls_records.h"

// Experiments
///////////
#define normal_execution 15
#define content_type_requirement 20
#define record_version_requirement 22
#define record_length_requirement 28
#define epoch_requirement 24
#define record_sequence_requirement 26
#define handshake_type_requirement 30
#define message_sequence_requirement 34
#define message_sequence_requirement_new 35
#define handshake_length_requirement 32
#define unfragmented_message_offset_requirement  38
#define unfragmented_message_length_requirement  40
#define handshake_version_requirement 46
#define fragment_length_requirement 48
#define cookie_length_requirement 50
#define session_id_length_requirement 52
#define CH0HVR_output_requirement 70
#define CH2SH_output_requirement 72
#define SH_cipher_suite_supported_output_requirement 74
#define signature_hash_algorithms_requirement 76
#define signature_hash_length_requirement 78
#define certificate_count_requirement 80
#define fragment_reassembly_requirement 36
#define fragment_message_length_requirement 44
#define fragment_message_sequence_requirement 42
#define extensions_length_requirement 54


#define RECORD_LAYER_SERVER_STATES AS_CH0_RECVD | AS_CH2_RECVD | AS_CKE_RECVD | AS_CCE_RECVD | AS_CEV_RECVD | AS_CCC_RECVD
#define RECORD_LAYER_CLIENT_STATES AS_HVR_RECVD | AS_SH_RECVD | AS_SCE_RECVD | AS_SKE_RECVD | AS_CER_RECVD | AS_SHD_RECVD | AS_SCC_RECVD
#define HANDSHAKE_LAYER_SERVER_STATES AS_CH0_RECVD | AS_CH2_RECVD | AS_CKE_RECVD | AS_CCE_RECVD | AS_CEV_RECVD
#define HANDSHAKE_LAYER_CLIENT_STATES AS_HVR_RECVD | AS_SH_RECVD | AS_SCE_RECVD | AS_SKE_RECVD | AS_CER_RECVD | AS_SHD_RECVD
typedef void (*monitor_handle)(RECORD *record, bool is_record_client_generated);

// typedef enum allowed_states allowed_states;
typedef enum allowed_states {
    AS_CH0_RECVD = 1 << CH0_RECVD, // 0th bit set
    AS_HVR_RECVD = 1 << HVR_RECVD, // 1st bit set
    AS_CH2_RECVD = 1 << CH2_RECVD, // 2nd bit set
    AS_SH_RECVD  = 1 << SH_RECVD,  // 3rd bit set
    AS_SCE_RECVD = 1 << SCE_RECVD, // 4th bit set
    AS_SKE_RECVD = 1 << SKE_RECVD, // 5th bit set
    AS_CER_RECVD = 1 << CER_RECVD, // 6th bit set
    AS_SHD_RECVD = 1 << SHD_RECVD, // 7th bit set
    AS_CCE_RECVD = 1 << CCE_RECVD, // 8th bit set
    AS_CKE_RECVD = 1 << CKE_RECVD, // 9th bit set
    AS_CEV_RECVD = 1 << CEV_RECVD, // 10th bit set
    AS_CCC_RECVD = 1 << CCC_RECVD, // 11th bit set
    AS_CFI_RECVD = 1 << CFI_RECVD, // 12th bit set
    AS_SCC_RECVD = 1 << SCC_RECVD, // 13th bit set
    AS_SFI_RECVD = 1 << SFI_RECVD  // 14th bit set
}allowed_states;

typedef struct
{
    monitor_handle handle;
    allowed_states valid_states;
}MONITOR;

monitor_handle set_monitor_handle(int experiment, SIDE side_to_check);
allowed_states set_monitor_valid_states(int experiment, SIDE side_to_check);
int determine_state_to_check(allowed_states as, SIDE side_to_check, bool is_cipher_psk);

// Record Layer
void is_content_type_valid_server(RECORD *record, bool is_record_client_generated);
void is_content_type_valid_client(RECORD *record, bool is_record_client_generated);
void is_epoch_valid_server(RECORD *record, bool is_record_client_generated);
void is_epoch_valid_client(RECORD *record, bool is_record_client_generated);
void is_record_sequence_number_valid_server(RECORD *records, bool is_record_client_generated);
void is_record_sequence_number_valid_client(RECORD *record, bool is_record_client_generated);
void is_record_version_valid_server(RECORD *record, bool is_record_client_generated);
void is_record_version_valid_client(RECORD *record, bool is_record_client_generated);
void is_record_length_valid_server(RECORD *record, bool is_record_client_generated);
void is_record_length_valid_client(RECORD *record, bool is_record_client_generated);

// Handshake Layer
void is_message_sequence_valid_server(RECORD *record, bool is_record_client_generated);
void is_message_sequence_valid_client(RECORD *record, bool is_record_client_generated);
void is_ch0_hvr_message_sequence_equal(RECORD *record, bool is_record_client_generated);
void is_handshake_type_valid_server(RECORD *record, bool is_record_client_generated);
void is_handshake_type_valid_client(RECORD *record, bool is_record_client_generated);
void is_extensions_length_valid_server(RECORD *record, bool is_record_client_generated);
void is_extensions_length_valid_client(RECORD *record, bool is_record_client_generated);
void is_unfragmented_message_offset_valid_server(RECORD *record, bool is_record_client_generated);
void is_unfragmented_message_offset_valid_client(RECORD *record, bool is_record_client_generated);
void is_unfragmented_message_length_valid_server(RECORD *record, bool is_record_client_generated);
void is_unfragmented_message_length_valid_client(RECORD *record, bool is_record_client_generated);
void is_handshake_version_valid_server(RECORD *record, bool is_record_client_generated);
void is_handshake_version_valid_client(RECORD *record, bool is_record_client_generated);
void is_fragment_length_valid_server(RECORD *record, bool is_record_client_generated);
void is_fragment_length_valid_client(RECORD *record, bool is_record_client_generated);
void is_cookie_length_valid_server(RECORD *record, bool is_record_client_generated);
void is_cookie_length_valid_client(RECORD *record, bool is_record_client_generated);
void is_session_id_length_valid_server(RECORD *record, bool is_record_client_generated);
void is_session_id_length_valid_client(RECORD *record, bool is_record_client_generated);
void is_ch2_sh_message_sequence_equal(RECORD *record, bool is_record_client_generated);
void is_sh_cipher_suite_supported(RECORD *record, bool is_record_client_generated);
void is_handshake_length_valid_server(RECORD *record, bool is_record_client_generated);
void is_handshake_length_valid_client(RECORD *record, bool is_record_client_generated);
void is_hash_sig_algorithm_equal(RECORD *record, bool is_record_client_generated);
void is_certificate_type_count_valid(RECORD *record, bool is_record_client_generated);
void is_hash_sig_algorithm_length_valid(RECORD *record, bool is_record_client_generated);
// Fragmentation
void is_fragment_reassembly_valid_server(RECORD *record, bool is_record_client_generated);
void is_fragment_reassembly_valid_client(RECORD *record, bool is_record_client_generated);
void is_message_seq_equal_in_fragments_server(RECORD *record, bool is_record_client_generated);
void is_message_seq_equal_in_fragments_client(RECORD *record, bool is_record_client_generated);
void is_message_length_equal_in_fragments_server(RECORD *record, bool is_record_client_generated);
void is_message_length_equal_in_fragments_client(RECORD *record, bool is_record_client_generated);
#endif // DTLS_MONITORS