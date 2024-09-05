#ifndef RECORDS_RECORDS_H
#define RECORDS_RECORDS_H

typedef struct RECORD_struct RECORD;

#include "stdint.h"
#include "memory.h"
#include <stdbool.h>
#include "klee/Support/Protocols/helper.h"
#include "klee/Protocols/dtls/dtls_states.h"

// Record Types
#define Handshake_REC 22
#define Change_Cipher_Spec_REC 20
#define Application_Data 23
#define Alert_REC 21
#define Heartbeat_REC 24

// Msg Types
#define Client_Hello_MSG 1
#define Server_Hello_MSG 2
#define Hello_Verify_Request_MSG 3
#define New_Session_ticket 4
#define Certificate_MSG 11
#define Server_Key_Exchange_MSG 12
#define Certificate_Request_MSG 13
#define Server_Hello_Done_MSG 14
#define Certificate_Verify_MSG 15
#define Client_Key_Exchange_MSG 16

// Record Layer lengths
#define CONTENT_TYPE_LENGTH 1
#define RECORD_VERSION_LENGTH 2
#define EPOCH_LENGTH 2
#define RECORD_SEQ_NUMBER_LENGTH 6
#define RECORD_LENGTH_LENGTH 2

// Fragment Layer lengths
#define HANDSHAKE_TYPE_LENGTH 1
#define HANDSHAKE_LENGTH_LENGTH 3
#define MESSAGE_SEQ_LENGTH 2
#define FRAGMENT_OFFSET_LENGTH 3
#define FRAGMENT_LENGTH_LENGTH 3


// CH lengths
#define HANDSHAKE_VERSION_LENGTH 2
#define RANDOM_LENGTH 32
#define SESSION_ID_LENGTH_LENGTH 1
#define COOKIE_LENGTH_LENGTH 1
#define CIPHER_SUITE_LENGTH_LENGTH 2
#define COMPRESSION_METHODS_LENGTH_LENGTH 1
#define EXTENSIONS_LENGTH_LENGTH 2

// CERTIFICATE RELATED lengths
#define CERTIFICATE_LENGTH_LENGTH 3
#define SIGNATURE_HASH_ALGORITHM_LENGTH 2
#define SIGNATURE_HASH_LENGTH_LENGTH 2
#define DISTINGUISHED_NAME_LENGTH 2
// SH lengths
#define CIPHER_SUITE_LENGTH 2

//
#define RECORD_HEADER_SIZE 13
#define FRAGMENT_HEADER_SIZE 12



typedef struct
{
    uint8_t handshake_version[HANDSHAKE_VERSION_LENGTH];
    uint8_t random[RANDOM_LENGTH];
    uint8_t session_id_length;
    uint8_t *session_id;
    uint8_t cookie_length;
    uint8_t *cookie;
    uint8_t cipher_suite_length[CIPHER_SUITE_LENGTH_LENGTH];
    uint8_t *cipher_suites;
    uint8_t compression_length;
    uint8_t compression_method;
    uint8_t extension_length[EXTENSIONS_LENGTH_LENGTH];
    uint8_t *extensions;
}CH;

typedef struct
{
    uint8_t *client_identity;
}CKE;

typedef struct
{
    uint8_t *payload;
}SKE;

typedef struct
{
    uint8_t ccs_msg;
}CCS;


typedef struct
{
    uint8_t *encrypted_message;
}APP;

typedef struct
{
    uint8_t type;
    uint8_t payload_length[2];
    uint8_t *payload;
    uint8_t *padding;
}HEARTBEAT;

typedef struct
{
    uint8_t level;
    uint8_t desc;
}ALERT;

typedef struct
{
    uint8_t handshake_version[HANDSHAKE_VERSION_LENGTH];
    uint8_t cookie_length;
    uint8_t* cookie;
}HVR;

typedef struct
{
    uint8_t handshake_version[HANDSHAKE_VERSION_LENGTH];
    uint8_t random[RANDOM_LENGTH];
    uint8_t session_id_length;
    uint8_t *session_id;
    uint8_t cipher_suite[CIPHER_SUITE_LENGTH_LENGTH];
    uint8_t compression_method;
    uint8_t extension_length[EXTENSIONS_LENGTH_LENGTH];
    uint8_t *extensions;

}SH;

typedef struct {
    uint8_t *payload;
}NEWSESSIONTICKET;

typedef struct
{
    uint8_t certificate_length[CERTIFICATE_LENGTH_LENGTH];
    uint8_t *certificate;
}CERTIFICATE;

typedef struct
{
    uint8_t signature_hash_algorithms[SIGNATURE_HASH_ALGORITHM_LENGTH];
    uint8_t signature_length[SIGNATURE_HASH_LENGTH_LENGTH];
    uint8_t *signature;
}CERTIFICATEVERIFY;

typedef struct
{
    uint8_t certificate_types_count;
    uint8_t *certificate_types;
    uint8_t signature_hash_algorithms_length[SIGNATURE_HASH_LENGTH_LENGTH];
    uint8_t *signature_hash_algorithms;
    uint8_t distinguished_names_length[DISTINGUISHED_NAME_LENGTH];
    uint8_t *distinguished_names;
    uint8_t *payload;
}CERTIFICATEREQUEST;

typedef struct
{
    uint8_t *payload;
}FRAGMENTED;

typedef union
{
    CH *client_hello;
    CKE *client_key_exchange;
    SKE *server_key_exchange;
    HVR *hello_verify_request;
    SH *server_hello;
    CERTIFICATE *certificate;
    CERTIFICATEVERIFY *certificate_verify;
    CERTIFICATEREQUEST *certificate_request;
    NEWSESSIONTICKET *new_session_ticket;
    FRAGMENTED *fragmented;
}BODY;

typedef struct
{
    uint8_t *encrypted_content;
    uint8_t handshake_type;
    uint8_t handshake_length[HANDSHAKE_LENGTH_LENGTH];
    uint8_t message_sequence[MESSAGE_SEQ_LENGTH];
    uint8_t fragment_offset[FRAGMENT_OFFSET_LENGTH];
    uint8_t fragment_length[FRAGMENT_LENGTH_LENGTH];
    BODY body;
}FRAGMENT;

typedef union{
    CCS change_cipher_spec;
    FRAGMENT *fragment;
    APP application_data;
    ALERT alert;
    HEARTBEAT heartbeat;
}REST;

struct RECORD_struct
{
    uint8_t content_type;
    uint8_t record_version[RECORD_VERSION_LENGTH];
    uint8_t epoch[EPOCH_LENGTH];
    uint8_t sequence_number[RECORD_SEQ_NUMBER_LENGTH];
    uint8_t record_length[RECORD_LENGTH_LENGTH];
    uint8_t *payload;
    bool is_client_generated;
    REST RES;
};

/////////
int parse_record(const uint8_t *datagram, RECORD *rec,  size_t *off, size_t datagram_size, bool is_client_originated);
int serialize_record(uint8_t **out_buffer, RECORD *rec, size_t rcvsize, RECORD *shadow_rec);                         
size_t handle_DTLS_fragmentation(const uint8_t *datagram, size_t datagram_size, uint8_t *out_datagram,
                                 QUEUE *queue, bool is_client_originated, int state_to_check);
void determine_record_content(RECORD *rec, char* record_content, size_t record_content_size, bool is_input);                                 
#endif //RECORDS_RECORDS_H