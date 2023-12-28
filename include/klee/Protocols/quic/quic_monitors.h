#ifndef QUIC_MONITORS
#define QUIC_MONITORS


#include "klee/Protocols/quic/quic_packets.h"
#include "klee/Protocols/quic/quic_states.h"
#include "klee/Support/Protocols/helper.h"



// Numebric Values for all the REQUIREMENTS
#define quic_normal_execution 0
#define initial_token_length_requirement 1
#define version_negotiation_requirement 2
#define reserved_bits_requirement 3
#define fixed_bit_requirement 4
#define dst_connection_id_length_requirement 5
#define src_connection_id_length_requirement 6
#define inconsistent_versions_requirement 7
#define frame_type_requirement 8
#define ack_ranges_requirement 9
#define empty_token_requirement 10
#define client_new_token_requirement 11
#define new_connection_id_length_requirement 12
#define retire_prior_to_requirement 13
#define handshake_done_receipt_requirement 14
#define stream_size_requirement 15
#define packet_length_requirement 16
#define new_token_length_requirement 17
#define crypto_length_requirement 18


typedef void (*quic_monitor_handle)(Packet *packet, bool is_packet_client_generated);
typedef bool (*quic_enabling_predicate)(quic_state state);

typedef struct
{
    quic_monitor_handle handle;
    quic_enabling_predicate enabling_predicate;
    bool is_packet_level;
}QUIC_MONITOR;

quic_monitor_handle set_quic_monitor_handle(int experiment, SIDE side_to_check);
quic_enabling_predicate set_quic_enabling_predicate(int experiment);
quic_state determine_quic_state_to_check(quic_enabling_predicate pred, SIDE side_to_check);
bool is_packet_level_monitor(const char *level_env);

/// Monitors

// Packet-level Monitors
void is_initial_token_length_valid_client(Packet *pkt, bool is_packet_client_generated);
void is_version_negotiation_done_correctly_server(Packet *pkt, bool is_packet_client_generated);
void are_reserved_bits_correct_server(Packet *pkt, bool is_packet_client_generated);
void are_reserved_bits_correct_client(Packet *pkt, bool is_packet_client_generated);
void is_fixed_bit_correct_server(Packet *pkt, bool is_packet_client_generated);
void is_fixed_bit_correct_client(Packet *pkt, bool is_packet_client_generated);
void is_dest_id_length_correct_server(Packet *pkt, bool is_packet_client_generated);
void is_dest_id_length_correct_client(Packet *pkt, bool is_packet_client_generated);
void is_src_id_length_correct_server(Packet *pkt, bool is_packet_client_generated);
void is_src_id_length_correct_client(Packet *pkt, bool is_packet_client_generated);
void are_inconsistent_versions_handled_correctly(Packet *pkt, bool is_packet_client_generated);
void is_packet_length_correct_server(Packet *pkt, bool is_packet_client_generated);
void is_packet_length_correct_client(Packet *pkt, bool is_packet_client_generated);

// Frame-level Monitors
void is_frame_type_valid_server(Packet *pkt, bool is_packet_client_generated);
void is_frame_type_valid_client(Packet *pkt, bool is_packet_client_generated);
void is_ack_range_valid_server(Packet *pkt, bool is_packet_client_generated);
void is_ack_range_valid_client(Packet *pkt, bool is_packet_client_generated);
void is_empty_token_handled_correctly_client(Packet *pkt, bool is_packet_client_generated);
void is_client_generated_new_token_handled_correctly(Packet *pkt, bool is_packet_client_generated);
void is_new_connection_id_length_correct_server(Packet *pkt, bool is_packet_client_generated);
void is_new_connection_id_length_correct_client(Packet *pkt, bool is_packet_client_generated);
void is_retire_less_equal_to_sequence_number_server(Packet *pkt, bool is_packet_client_generated);
void is_retire_less_equal_to_sequence_number_client(Packet *pkt, bool is_packet_client_generated);
void is_client_generated_handshake_done_handled_correctly(Packet *pkt, bool is_packet_client_generated);
void is_oversized_stream_handled_correctly_server(Packet *pkt, bool is_packet_client_generated);
void is_oversized_stream_handled_correctly_client(Packet *pkt, bool is_packet_client_generated);
void is_new_token_length_correct_server(Packet *pkt, bool is_packet_client_generated);
void is_new_token_length_correct_client(Packet *pkt, bool is_packet_client_generated);
void is_crypto_length_correct_server(Packet *pkt, bool is_packet_client_generated);
void is_crypto_length_correct_client(Packet *pkt, bool is_packet_client_generated);

/// Enabling states
bool initial_token_length_enabling_predicate(quic_state state);
bool version_negotation_enabling_predicate(quic_state state);
bool reserved_bits_enabling_predicate(quic_state state);
bool fixed_bit_enabling_predicate(quic_state state);
bool dest_id_length_enabling_predicate(quic_state state);
bool src_id_length_enabling_predicate(quic_state state);
bool inconsistent_versions_enabling_predicate(quic_state state);
bool packet_length_enabling_predicate(quic_state state);

bool frame_type_enabling_predicate(quic_state state);
bool ack_range_enabling_predicate(quic_state state);
bool empty_token_enabling_predicate(quic_state state);
bool client_generated_new_token_enabling_predicate(quic_state state);
bool new_connection_id_length_enabling_predicate(quic_state state);
bool retire_less_equal_to_sequence_number_enabling_predicate(quic_state state);
bool client_generated_handshake_done_enabling_predicate(quic_state state);
bool oversized_stream_enabling_predicate(quic_state state);
bool new_token_length_enabling_predicate(quic_state state);
bool crypto_length_enabling_predicate(quic_state state);

#endif