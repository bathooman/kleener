#ifndef DTLS_DATAGRAM
#define DTLS_DATAGRAM

#include "klee/Protocols/dtls/dtls_records.h"
#include "klee/Protocols/dtls/dtls_monitors.h"
#include "klee/Protocols/quic/quic_monitors.h"

int handle_DTLS_datagram(uint8_t *datagram, size_t datagram_size, uint8_t *out_datagram,
                         bool is_client_originated, monitor_handle monitor_handle, int state_to_check);

int handle_quic_datagram(uint8_t *datagram, size_t datagram_size, uint8_t *out_datagram, 
                        bool is_client_originated, QUIC_MONITOR monitor, quic_state state_to_check);                         

#endif