#===------------------------------------------------------------------------===#
#
#                     The KLEE Symbolic Virtual Machine
#
# This file is distributed under the University of Illinois Open Source
# License. See LICENSE.TXT for details.
#
#===------------------------------------------------------------------------===#
# Set up
set(LIB_PREFIX "RuntimeIntrinsic")
set(SRC_FILES
        dso_handle.c
        klee_choose.c
        klee_div_zero_check.c
        klee_int.c
        klee_is_replay.c
        klee_overshift_check.c
        klee_range.c
        Protocols/datagram.c
        Protocols/helper.c
        Protocols/DTLS/dtls_records.c
        Protocols/DTLS/dtls_socket_model.c
        Protocols/DTLS/dtls_states.c
        Protocols/DTLS/monitors/monitors.c
	Protocols/DTLS/monitors/content-type.c
	Protocols/DTLS/monitors/epoch.c
	Protocols/DTLS/monitors/record-sequence-number.c
	Protocols/DTLS/monitors/message-sequence-number.c
	Protocols/DTLS/monitors/unfragmented-message-offset.c
	Protocols/DTLS/monitors/fragment-length.c
	Protocols/DTLS/monitors/unfragmented-message-length.c
	Protocols/DTLS/monitors/handshake-version.c
	Protocols/DTLS/monitors/cookie-length.c
	Protocols/DTLS/monitors/sessionid-length.c
	Protocols/DTLS/monitors/ch0-hvr-message-sequence.c
	Protocols/DTLS/monitors/ch2-sh-message-sequence.c
	Protocols/DTLS/monitors/sh-cipher-suite.c
	Protocols/DTLS/monitors/handshake-length.c
	Protocols/DTLS/monitors/fragment-reassembly.c
	Protocols/DTLS/monitors/handshake-type.c
	Protocols/DTLS/monitors/record-version.c
	Protocols/DTLS/monitors/record-length.c
	Protocols/DTLS/monitors/extensions-length.c
	Protocols/DTLS/monitors/message-sequence-in-fragments.c
	Protocols/DTLS/monitors/message-length-in-fragments.c
	Protocols/DTLS/monitors/sighash-algorithms.c
	Protocols/DTLS/monitors/certificate-type-count.c
	Protocols/DTLS/monitors/sighash-algorithms-length.c
	Protocols/QUIC/quic_socket_model.c
	Protocols/QUIC/quic_packets.c
	Protocols/QUIC/quic_states.c
	Protocols/QUIC/monitors/quicmonitors.c
	Protocols/QUIC/monitors/token-length.c
	Protocols/QUIC/monitors/version-negotiation.c
	Protocols/QUIC/monitors/reserved-bits.c
	Protocols/QUIC/monitors/fixed-bit.c
	Protocols/QUIC/monitors/src-connection-id-length.c
	Protocols/QUIC/monitors/dest-connection-id-length.c
	Protocols/QUIC/monitors/inconsistent-versions.c
	Protocols/QUIC/monitors/packet-length.c
	Protocols/QUIC/monitors/frame-type.c
	Protocols/QUIC/monitors/ack-ranges.c
	Protocols/QUIC/monitors/empty-token.c
	Protocols/QUIC/monitors/client-new-token.c
	Protocols/QUIC/monitors/new-connection-id-length.c
	Protocols/QUIC/monitors/retire-prior-to.c
	Protocols/QUIC/monitors/handshake-done-receipt.c
	Protocols/QUIC/monitors/stream-size.c
	Protocols/QUIC/monitors/new-token-length.c
	Protocols/QUIC/monitors/crypto-length.c
        )

# Build it
include("${CMAKE_SOURCE_DIR}/cmake/compile_bitcode_library.cmake")
prefix_with_path("${SRC_FILES}" "${CMAKE_CURRENT_SOURCE_DIR}/" prefixed_files)
add_bitcode_library_targets("${LIB_PREFIX}" "${prefixed_files}" "-std=gnu89" "")