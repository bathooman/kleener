#ifndef COAP_PACKETS_H
#define COAP_PACKETS_H

#include <stdio.h>
#include <stdint.h>
#include <stddef.h>

#define COAP_MAX_TOKEN_LENGTH 8 // 8 bytes
#define COAP_MAX_OPTIONS_LENGTH 16 // Arbitrary limit

/**
 * @see https://datatracker.ietf.org/doc/html/rfc7252#section-3
 */
#define COAP_TYPE_CON 0
#define COAP_TYPE_NON 1
#define COAP_TYPE_ACK 2
#define COAP_TYPE_RST 3

#define COAP_OPTION_IF_MATCH 1
#define COAP_OPTION_URI_HOST 3
#define COAP_OPTION_ETAG 4
#define COAP_OPTION_IF_NONE_MATCH 5
#define COAP_OPTION_URI_PORT 7
#define COAP_OPTION_LOCATION_PATH 8
#define COAP_OPTION_URI_PATH 11
#define COAP_OPTION_CONTENT_FORMAT 12
#define COAP_OPTION_MAX_AGE 14
#define COAP_OPTION_URI_QUERY 15
#define COAP_OPTION_ACCEPT 17
#define COAP_OPTION_LOCATION_QUERY 20
#define COAP_OPTION_PROXY_URI 35
#define COAP_OPTION_PROXY_SCHEME 39
#define COAP_OPTION_SIZE1 60

#define COAP_OPTION_NIBBLE_1BYTE_EXT 13
#define COAP_OPTION_NIBBLE_2BYTE_EXT 14
#define COAP_OPTION_NIBBLE_RESERVED 15

#define COAP_CODE_EMPTY 0x00
#define COAP_CODE_GET 0x01
#define COAP_CODE_POST 0x02
#define COAP_CODE_PUT 0x03
#define COAP_CODE_DELETE 0x04

#define COAP_PAYLOAD_MARKER 0xFF

typedef struct
{
    uint8_t version;
    uint8_t type;
    uint8_t token_length;
    uint8_t code;
    uint16_t message_id;
} CoapHeader;

typedef struct
{
    uint16_t number;
    uint16_t length;
    const uint8_t* value;
} CoapOption;

typedef struct
{
    CoapHeader header;
    uint8_t token[COAP_MAX_TOKEN_LENGTH];
    CoapOption options[COAP_MAX_OPTIONS_LENGTH];
    size_t num_options;
    const uint8_t* payload;
    size_t payload_length;
} CoapMessage;

int parse_coap_message(const uint8_t* buf, size_t data_length, CoapMessage* message);

/* Inverse of parse_coap_message — see comment in coap_packets.c.
 * `shadow` carries the concrete sizes used for variable-length copies.
 * Returns the number of bytes written to `out_buf` (>= 4) on success, or -1
 * on error (buffer too small / malformed). */
int serialize_coap_message(const CoapMessage *message,
                           const CoapMessage *shadow,
                           uint8_t *out_buf,
                           size_t out_buf_size);

#endif
