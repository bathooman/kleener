//
// Created by hooman on 2020-12-18.
//
#include <stdint.h>
#include "klee/Protocols/dtls/dtls_records.h"
#include "klee/Protocols/dtls/dtls_states.h"
#include "klee/Support/Protocols/helper.h"
#include "klee/klee.h"
#include <stdio.h>
#include <memory.h>
#include <errno.h>
#include <stdlib.h>
#include <assert.h>
#include <stdbool.h>
#include <inttypes.h>

/////////////////////// Parser Functions

static void parse_CH(uint8_t *buf, CH *client_hello, size_t fragment_size)
{
    uint8_t *msg = buf;

    memcpy(&client_hello->handshake_version, msg, HANDSHAKE_VERSION_LENGTH);
    msg += HANDSHAKE_VERSION_LENGTH; // Get past the Handshake Version

    memcpy(&client_hello->random, msg, RANDOM_LENGTH);
    msg += RANDOM_LENGTH; // Get past the Random

    memcpy(&client_hello->session_id_length, msg, SESSION_ID_LENGTH_LENGTH);
    msg += SESSION_ID_LENGTH_LENGTH; // Get past the session id Length

    if (client_hello->session_id_length > 0)
    {
        client_hello->session_id = malloc(client_hello->session_id_length);
        memcpy(client_hello->session_id, msg, client_hello->session_id_length);
        msg += client_hello->session_id_length; // Get past the Session ID
    }

    memcpy(&client_hello->cookie_length, msg, COOKIE_LENGTH_LENGTH);
    msg += COOKIE_LENGTH_LENGTH; // Get past the Cookie Length

    if (client_hello->cookie_length > 0)
    {
        client_hello->cookie = malloc(client_hello->cookie_length);
        memcpy(client_hello->cookie, msg, client_hello->cookie_length);
        msg += client_hello->cookie_length; // Get past the cookie
    }

    memcpy(&client_hello->cipher_suite_length, msg, CIPHER_SUITE_LENGTH_LENGTH);
    msg += CIPHER_SUITE_LENGTH_LENGTH; //Get past the Cipher Suite Length

    size_t cipher_suite_size = byte_to_int(client_hello->cipher_suite_length, CIPHER_SUITE_LENGTH_LENGTH);
    client_hello->cipher_suites = malloc(cipher_suite_size);
    memcpy(client_hello->cipher_suites, msg, cipher_suite_size);
    msg += cipher_suite_size; // Get past the cipher suites

    memcpy(&client_hello->compression_length, msg, COMPRESSION_METHODS_LENGTH_LENGTH);
    msg += COMPRESSION_METHODS_LENGTH_LENGTH; // Get past the compression length

    client_hello->compression_method = (*msg);
    msg += 1; // Get past the compression methods

    if (fragment_size > msg - buf)
    {
        memcpy(client_hello->extension_length, msg, EXTENSIONS_LENGTH_LENGTH);
        msg += EXTENSIONS_LENGTH_LENGTH; // Get past the Extension Length

        size_t extension_length = byte_to_int(client_hello->extension_length, EXTENSIONS_LENGTH_LENGTH);
        client_hello->extensions = malloc(extension_length);
        memcpy(client_hello->extensions, msg, extension_length);
        msg += extension_length; // Get past the Extensions

        assert(fragment_size == msg - buf); // At this point the whole fragment should be parsed
    }
}

static void parse_CKE(uint8_t *buf, CKE *client_key_exchange, size_t fragment_length)
{
    uint8_t *msg = buf;

    client_key_exchange->client_identity = malloc(fragment_length);
    memcpy(client_key_exchange->client_identity, msg, fragment_length);
    msg += fragment_length; // Get past the fragment

    assert(fragment_length == msg - buf); // Unnecessary Sanity check
}

static void parse_SKE(uint8_t *buf, SKE *server_key_exchange, size_t fragment_length)
{
    uint8_t *msg = buf;

    server_key_exchange->payload = malloc(fragment_length);
    memcpy(server_key_exchange->payload, msg, fragment_length);
    msg += fragment_length; // Get past the payload

    assert(fragment_length == msg - buf); // Unnecessary Sanity check
}

static void parse_HVR(uint8_t *buf, HVR *hello_verify_request, size_t fragment_length)
{
    uint8_t *msg = buf;

    memcpy(hello_verify_request->handshake_version, msg, HANDSHAKE_VERSION_LENGTH);
    msg += HANDSHAKE_VERSION_LENGTH; // Get past the Handshake version

    hello_verify_request->cookie_length = (*msg);
    msg+= COOKIE_LENGTH_LENGTH; // Get past the cookie length

    size_t cookie_length = byte_to_int(&hello_verify_request->cookie_length, COOKIE_LENGTH_LENGTH);
    hello_verify_request->cookie = malloc(cookie_length);
    memcpy(hello_verify_request->cookie, msg, cookie_length);
    msg += cookie_length; // Get past the cookie

    assert(fragment_length == msg - buf);
}

static void parse_SH(uint8_t *buf, SH *server_hello, size_t fragment_length)
{
    uint8_t *msg = buf;

    memcpy(server_hello->handshake_version, msg, HANDSHAKE_VERSION_LENGTH);
    msg += HANDSHAKE_VERSION_LENGTH; // Get past the handshake version

    memcpy(server_hello->random, msg, RANDOM_LENGTH);
    msg += RANDOM_LENGTH; // Get past the random

    server_hello->session_id_length = (*msg);
    msg += SESSION_ID_LENGTH_LENGTH; // Get past the session id length

    if (server_hello->session_id_length > 0)
    {
        server_hello->session_id = malloc(server_hello->session_id_length);
        memcpy(server_hello->session_id, msg, server_hello->session_id_length);
        msg += server_hello->session_id_length; // Get past the session id
    }

    memcpy(server_hello->cipher_suite, msg, CIPHER_SUITE_LENGTH_LENGTH);
    msg += CIPHER_SUITE_LENGTH_LENGTH; // Get past the cipher Suite

    server_hello->compression_method = (*msg);
    msg += COMPRESSION_METHODS_LENGTH_LENGTH; // Get past the compression method

    if (fragment_length > msg - buf)
    {
        memcpy(server_hello->extension_length, msg, EXTENSIONS_LENGTH_LENGTH);
        msg += EXTENSIONS_LENGTH_LENGTH; // Get past the extension length

        size_t extension_length = byte_to_int(server_hello->extension_length, EXTENSIONS_LENGTH_LENGTH);
        server_hello->extensions = malloc(extension_length);
        memcpy(server_hello->extensions, msg, extension_length);
        msg += extension_length; // Get past the extensions
    }
    assert(fragment_length == msg - buf);
}

static void parse_NST(uint8_t *buf, NEWSESSIONTICKET *new_session_ticket, size_t fragment_length)
{
    uint8_t *msg = buf;

    new_session_ticket->payload = malloc(fragment_length);
    memcpy(new_session_ticket->payload, msg, fragment_length);
    msg += fragment_length; // Get past the fragment

    assert(fragment_length == msg - buf); // Unnecessary Sanity check
}

static void parse_CE(uint8_t *buf, CERTIFICATE *certificate, size_t fragment_length)
{
    uint8_t *msg = buf;

    memcpy(certificate->certificate_length, msg, CERTIFICATE_LENGTH_LENGTH);
    msg += CERTIFICATE_LENGTH_LENGTH; // Get past the Certificate Length

    size_t certificate_length = byte_to_int(certificate->certificate_length, CERTIFICATE_LENGTH_LENGTH);
    certificate->certificate = malloc(certificate_length);
    memcpy(certificate->certificate, msg, certificate_length);
    msg += certificate_length; // Get past the Certificate

    assert(fragment_length == msg - buf); // Unnecessary Sanity check

}

static void parse_CEV(uint8_t *buf, CERTIFICATEVERIFY *certificateverify, size_t fragment_length)
{
    uint8_t *msg = buf;

    memcpy(certificateverify->signature_hash_algorithms, msg, SIGNATURE_HASH_ALGORITHM_LENGTH);
    msg += SIGNATURE_HASH_ALGORITHM_LENGTH; // Get past the signature algorithm

    memcpy(certificateverify->signature_length, msg, SIGNATURE_HASH_LENGTH_LENGTH);
    msg += SIGNATURE_HASH_LENGTH_LENGTH; // Get past the Signature Length

    size_t signature_length = byte_to_int(certificateverify->signature_length, SIGNATURE_HASH_LENGTH_LENGTH);
    certificateverify->signature = malloc(signature_length);
    memcpy(certificateverify->signature, msg, signature_length);
    msg += signature_length;

    assert(fragment_length == msg - buf); // Unnecessary Sanity check
}

/* RFC 5246#section-7.4.4

    struct {
        ClientCertificateType certificate_types<1..2^8-1>;
        SignatureAndHashAlgorithm
        supported_signature_algorithms<2^16-1>;
        DistinguishedName certificate_authorities<0..2^16-1>;
    } CertificateRequest;
    
*/
static void parse_CER(uint8_t *buf, CERTIFICATEREQUEST *certificaterequest, size_t fragment_length)
{
    
    uint8_t *msg = buf;
    certificaterequest->certificate_types_count = *msg;
    msg += 1; // Get past the certificate_types_count

    certificaterequest->certificate_types = malloc(certificaterequest->certificate_types_count);
    memcpy(certificaterequest->certificate_types, msg, certificaterequest->certificate_types_count);
    msg += certificaterequest->certificate_types_count; // Get past the certificate_types

    memcpy(certificaterequest->signature_hash_algorithms_length, msg, SIGNATURE_HASH_LENGTH_LENGTH);
    msg += SIGNATURE_HASH_LENGTH_LENGTH; // Get past the signature length

    size_t signature_hash_length = byte_to_int(certificaterequest->signature_hash_algorithms_length, SIGNATURE_HASH_LENGTH_LENGTH);
    certificaterequest->signature_hash_algorithms = malloc(signature_hash_length);
    memcpy(certificaterequest->signature_hash_algorithms, msg, signature_hash_length);
    msg += signature_hash_length; // Get past the signature

    memcpy(certificaterequest->distinguished_names_length, msg, DISTINGUISHED_NAME_LENGTH);
    msg += DISTINGUISHED_NAME_LENGTH; // Get past the distinguished names length

    size_t distinguished_names_length = byte_to_int(certificaterequest->distinguished_names_length, DISTINGUISHED_NAME_LENGTH);
    certificaterequest->distinguished_names = malloc(distinguished_names_length);
    memcpy(certificaterequest->distinguished_names, msg, distinguished_names_length);
    msg += distinguished_names_length; // Get past the distinguished names

    assert(fragment_length == msg - buf); // Unnecessary Sanity check
}

static int parse_fragment(RECORD *rec, size_t record_length)
{
    uint8_t *msg = rec->payload;

    rec->RES.fragment->handshake_type = (*msg);
    msg += HANDSHAKE_TYPE_LENGTH; // Get past the Handshake Type

    memcpy(&rec->RES.fragment->handshake_length, msg, HANDSHAKE_LENGTH_LENGTH);
    msg += HANDSHAKE_LENGTH_LENGTH; // Get past the Handshake Length

    memcpy(&rec->RES.fragment->message_sequence, msg, MESSAGE_SEQ_LENGTH);
    msg += MESSAGE_SEQ_LENGTH; // Get past the Message Sequence

    memcpy(&rec->RES.fragment->fragment_offset, msg, FRAGMENT_OFFSET_LENGTH);
    msg += FRAGMENT_OFFSET_LENGTH; // Get past the Fagment Offset

    memcpy(&rec->RES.fragment->fragment_length, msg, FRAGMENT_LENGTH_LENGTH);
    msg += FRAGMENT_LENGTH_LENGTH; // Get past the Fragment Length

    size_t fragment_length = byte_to_int(rec->RES.fragment->fragment_length, FRAGMENT_LENGTH_LENGTH);
    size_t handshake_length = byte_to_int(rec->RES.fragment->handshake_length, HANDSHAKE_LENGTH_LENGTH);

    // Check if the message is unfragmented
    if (handshake_length == fragment_length)
    {
        switch (rec->RES.fragment->handshake_type)
        {
            case Client_Hello_MSG:
                rec->RES.fragment->body.client_hello = malloc(sizeof(CH));
                parse_CH(msg, rec->RES.fragment->body.client_hello, fragment_length);
                break;

            case Client_Key_Exchange_MSG:
                rec->RES.fragment->body.client_key_exchange = malloc(sizeof(CKE));
                parse_CKE(msg, rec->RES.fragment->body.client_key_exchange, fragment_length);
                break;

            case Server_Key_Exchange_MSG:
                rec->RES.fragment->body.server_key_exchange = malloc(sizeof(SKE));
                parse_SKE(msg, rec->RES.fragment->body.server_key_exchange, fragment_length);
                break;

            case Hello_Verify_Request_MSG:
                rec->RES.fragment->body.hello_verify_request = malloc(sizeof(HVR));
                parse_HVR(msg, rec->RES.fragment->body.hello_verify_request, fragment_length);
                break;

            case Server_Hello_MSG:
                rec->RES.fragment->body.server_hello = malloc(sizeof(SH));
                parse_SH(msg, rec->RES.fragment->body.server_hello, fragment_length);
                break;

            case New_Session_ticket:
                rec->RES.fragment->body.new_session_ticket = malloc(sizeof(NEWSESSIONTICKET));
                parse_NST(msg, rec->RES.fragment->body.new_session_ticket, fragment_length);
                break;

            case Certificate_MSG:
                rec->RES.fragment->body.certificate = malloc(sizeof(CERTIFICATE));
                parse_CE(msg, rec->RES.fragment->body.certificate, fragment_length);
                break;

            case Certificate_Verify_MSG:
                rec->RES.fragment->body.certificate_verify = malloc(sizeof(CERTIFICATEVERIFY));
                parse_CEV(msg, rec->RES.fragment->body.certificate_verify, fragment_length);
                break;

            case Certificate_Request_MSG:
                rec->RES.fragment->body.certificate_request = malloc(sizeof(CERTIFICATEREQUEST));
                parse_CER(msg, rec->RES.fragment->body.certificate_request, fragment_length);
                break;

            case Server_Hello_Done_MSG:
                // We do not need to parse Server Hello done since there is nothing in the frame
                break;
        }
    }
    else if (handshake_length > fragment_length)
    {
        switch (rec->RES.fragment->handshake_type)
        {
            case Certificate_MSG:
            case Client_Key_Exchange_MSG:
            case Server_Hello_MSG:
            case Server_Key_Exchange_MSG:
                rec->RES.fragment->body.fragmented = malloc(sizeof(FRAGMENTED));
                rec->RES.fragment->body.fragmented->payload = malloc(fragment_length);
                memcpy(rec->RES.fragment->body.fragmented->payload, msg, fragment_length);
                break;
        }
    }
    return 0;
}

static void parse_heartbeat(RECORD *rec, size_t record_length)
{
    uint8_t *msg = rec->payload;
    rec->RES.heartbeat.type = *msg;
    msg += 1; // Get past the type

    memcpy(rec->RES.heartbeat.payload_length, msg, 2);
    msg += 2; // Get past the payload length

    size_t payload_length = byte_to_int(rec->RES.heartbeat.payload_length, 2);
    rec->RES.heartbeat.payload = malloc(payload_length);
    memcpy(rec->RES.heartbeat.payload, msg, payload_length);
    msg += payload_length; // Get past the payload

    /* RFC 6520 Section 4
    The padding is random content that MUST be ignored by the
    receiver.  The length of a HeartbeatMessage is TLSPlaintext.length
    for TLS and DTLSPlaintext.length for DTLS.  Furthermore, the
    length of the type field is 1 byte, and the length of the
    payload_length is 2.  Therefore, the padding_length is
    TLSPlaintext.length - payload_length - 3 for TLS and
    DTLSPlaintext.length - payload_length - 3 for DTLS.  The
    padding_length MUST be at least 16.
    */
    size_t padding_length = record_length - payload_length - 3;
    rec->RES.heartbeat.padding = malloc(padding_length);
    memcpy(rec->RES.heartbeat.padding, msg, padding_length);
}

int parse_record(const uint8_t *datagram, RECORD *rec,  size_t *off, size_t datagram_size, bool is_client_originated)
{
    uint8_t *msg = (uint8_t *) datagram + *off;
    uint8_t *point_to_beginning = (uint8_t *) datagram + *off;

    rec->content_type = (*msg);
    msg += CONTENT_TYPE_LENGTH; // Get past the Content Type

    memcpy(&rec->record_version, msg, RECORD_VERSION_LENGTH);
    msg += RECORD_VERSION_LENGTH; // Get past the Record Version

    memcpy(&rec->epoch, msg, EPOCH_LENGTH);
    msg += EPOCH_LENGTH; // Get past the Epoch


    memcpy(&rec->sequence_number, msg, RECORD_SEQ_NUMBER_LENGTH);
    msg += RECORD_SEQ_NUMBER_LENGTH; // Get past the Sequence Number

    memcpy(&rec->record_length, msg, RECORD_LENGTH_LENGTH);
    msg += RECORD_LENGTH_LENGTH; // Get past the Record Length

    size_t record_length = byte_to_int(rec->record_length, RECORD_LENGTH_LENGTH);
    rec->payload = malloc(record_length);
    memcpy(rec->payload, msg, record_length); // Storing the rest of the record in the payload for further parsing
    msg += record_length; // Get past the rest of this DTLS record

    rec->is_client_generated = is_client_originated; // Store the record origin

    // We parse the content of the record here using the payload
    if (rec->content_type == Handshake_REC)
    {
        if (byte_to_int(rec->epoch, EPOCH_LENGTH) == 0)
        {
            rec->RES.fragment = malloc(sizeof(FRAGMENT));
            parse_fragment(rec, record_length);
        }
        else
        {
            rec->RES.fragment = malloc(sizeof(FRAGMENT));
            rec->RES.fragment->encrypted_content = malloc(record_length);
            memcpy(rec->RES.fragment->encrypted_content, rec->payload, record_length);
        }
    }
    else if (rec->content_type == Change_Cipher_Spec_REC)
    {
        memcpy(&rec->RES.change_cipher_spec.ccs_msg, rec->payload, record_length);
    }
    else if (rec->content_type == Application_Data)
    {
        rec->RES.application_data.encrypted_message = malloc(record_length);
        memcpy(rec->RES.application_data.encrypted_message, rec->payload, record_length);
    }
    else if (rec->content_type == Alert_REC)
    {
        rec->RES.alert.level = rec->payload[0];
        rec->RES.alert.desc = rec->payload[1];
    }
    else if (rec->content_type == Heartbeat_REC)
    {
        parse_heartbeat(rec, record_length);
    }

    *off += msg - point_to_beginning;
    return msg - point_to_beginning;
}

/////////////////////// Serializer Functions


static void serialize_CH(uint8_t **out_buffer, CH *rec, size_t fragment_length, CH *shadow_rec)
{

    uint8_t *pointer_to_beginning = *out_buffer;

    memcpy(*out_buffer, rec->handshake_version, HANDSHAKE_VERSION_LENGTH);
    *out_buffer += HANDSHAKE_VERSION_LENGTH; // Get past the Handshake Version

    memcpy(*out_buffer, rec->random, RANDOM_LENGTH);
    *out_buffer += RANDOM_LENGTH; // Get past the Random

    **out_buffer = (rec->session_id_length);
    *out_buffer += SESSION_ID_LENGTH_LENGTH; // Get past the session ID Length

    if (shadow_rec->session_id_length > 0)
    {
        memcpy(*out_buffer, rec->session_id, shadow_rec->session_id_length);
        *out_buffer += shadow_rec->session_id_length; // Get past the Session ID
    }

    **out_buffer = rec->cookie_length;
    *out_buffer += COOKIE_LENGTH_LENGTH; // Get past the Cookie Length

    if (shadow_rec->cookie_length > 0)
    {
        memcpy(*out_buffer, rec->cookie, shadow_rec->cookie_length);
        *out_buffer += shadow_rec->cookie_length; // Get past the Cookie
    }

    memcpy(*out_buffer, rec->cipher_suite_length, CIPHER_SUITE_LENGTH_LENGTH);
    *out_buffer += CIPHER_SUITE_LENGTH_LENGTH; //Get past the Cipher Suites Length

    size_t cipher_suite_size = byte_to_int(shadow_rec->cipher_suite_length, CIPHER_SUITE_LENGTH_LENGTH);
    memcpy(*out_buffer, rec->cipher_suites, cipher_suite_size);
    *out_buffer += cipher_suite_size; // Get past the Cipher Suites

    **out_buffer = rec->compression_length;
    *out_buffer += COMPRESSION_METHODS_LENGTH_LENGTH; // Get past the Compression Length

    **out_buffer = rec->compression_method;
    *out_buffer += 1; // Get past the Compression method


    if (rec->extensions != NULL && fragment_length > *out_buffer - pointer_to_beginning)
    {
        size_t Extension_length = byte_to_int(shadow_rec->extension_length, EXTENSIONS_LENGTH_LENGTH);

        memcpy(*out_buffer, rec->extension_length, EXTENSIONS_LENGTH_LENGTH);
        *out_buffer += EXTENSIONS_LENGTH_LENGTH; // Get past the extension length

        memcpy(*out_buffer, rec->extensions, Extension_length);
        *out_buffer += Extension_length; // Get past the Extensions
    }
}

static void serialize_HVR(uint8_t **out_buffer, HVR *rec, size_t fragment_length, HVR *shadow_rec)
{
    memcpy(*out_buffer, rec->handshake_version, HANDSHAKE_VERSION_LENGTH);
    *out_buffer += HANDSHAKE_VERSION_LENGTH; // Get past the Handshake Version

    **out_buffer = rec->cookie_length;
    *out_buffer += COOKIE_LENGTH_LENGTH; // Get past the Cookie Length

    memcpy(*out_buffer, rec->cookie, shadow_rec->cookie_length);
    *out_buffer += shadow_rec->cookie_length; // Get past the Cookie
}

static void serialize_SH(uint8_t **out_buffer, SH *rec, size_t fragment_length, SH *shadow_rec)
{
    uint8_t *pointer_to_beginning = *out_buffer;

    memcpy(*out_buffer, rec->handshake_version, HANDSHAKE_VERSION_LENGTH);
    *out_buffer += HANDSHAKE_VERSION_LENGTH; // Get past the Handshake Version

    memcpy(*out_buffer, rec->random, RANDOM_LENGTH);
    *out_buffer += RANDOM_LENGTH;

    **out_buffer = rec->session_id_length;
    *out_buffer += SESSION_ID_LENGTH_LENGTH; // Get past the Session Id Length

    if (shadow_rec->session_id_length > 0)
    {
        memcpy(*out_buffer, rec->session_id, shadow_rec->session_id_length);
        *out_buffer += shadow_rec->session_id_length;
    }

    memcpy(*out_buffer, rec->cipher_suite, CIPHER_SUITE_LENGTH_LENGTH);
    *out_buffer += CIPHER_SUITE_LENGTH_LENGTH; // Get Past the Cipher Suite

    **out_buffer = rec->compression_method;
    *out_buffer += 1; // Get past the compression method

    if (shadow_rec->extensions != NULL && fragment_length > *out_buffer - pointer_to_beginning)
    {
        size_t Extension_length = byte_to_int(shadow_rec->extension_length, EXTENSIONS_LENGTH_LENGTH);

        memcpy(*out_buffer, rec->extension_length, EXTENSIONS_LENGTH_LENGTH);
        *out_buffer += EXTENSIONS_LENGTH_LENGTH; // Get past the Extension Length

        memcpy(*out_buffer, rec->extensions, Extension_length);
        *out_buffer += Extension_length;
    }
}

static void serialize_CE(uint8_t **out_buffer, CERTIFICATE *rec, size_t fragment_length, CERTIFICATE *shadow_rec)
{
    memcpy(*out_buffer, rec->certificate_length, CERTIFICATE_LENGTH_LENGTH);
    *out_buffer += CERTIFICATE_LENGTH_LENGTH; // Get past the certificate length

    size_t certificate_length = byte_to_int(rec->certificate_length, CERTIFICATE_LENGTH_LENGTH);
    memcpy(*out_buffer, rec->certificate, certificate_length);
    *out_buffer += certificate_length; // Get past the certificate
}

static void serialize_CER(uint8_t **out_buffer, CERTIFICATEREQUEST *rec, size_t fragment_length, CERTIFICATEREQUEST *shadow_rec)
{
    **out_buffer = rec->certificate_types_count;
    *out_buffer += 1; // Get past the certificate type count

    memcpy(*out_buffer, rec->certificate_types, shadow_rec->certificate_types_count);
    *out_buffer += rec->certificate_types_count; // Get past the certificate types

    memcpy(*out_buffer, rec->signature_hash_algorithms_length, SIGNATURE_HASH_LENGTH_LENGTH);
    *out_buffer += SIGNATURE_HASH_LENGTH_LENGTH; // Get past the signature length

    size_t signature_length = byte_to_int(shadow_rec->signature_hash_algorithms_length, SIGNATURE_HASH_LENGTH_LENGTH);
    memcpy(*out_buffer, rec->signature_hash_algorithms, signature_length);
    *out_buffer += signature_length; // Get past the signature

    memcpy(*out_buffer, rec->distinguished_names_length, DISTINGUISHED_NAME_LENGTH);
    *out_buffer += DISTINGUISHED_NAME_LENGTH; // Get past the distinguished name length

    size_t distinguished_name_length = byte_to_int(shadow_rec->distinguished_names_length, DISTINGUISHED_NAME_LENGTH);
    memcpy(*out_buffer, rec->distinguished_names, distinguished_name_length);
    *out_buffer += distinguished_name_length;

}

static void serialize_CEV(uint8_t **out_buffer, CERTIFICATEVERIFY *rec, size_t fragment_length, CERTIFICATEVERIFY *shadow_rec)
{
    memcpy(*out_buffer, rec->signature_hash_algorithms, SIGNATURE_HASH_ALGORITHM_LENGTH);
    *out_buffer += SIGNATURE_HASH_ALGORITHM_LENGTH; //Get past the signature algorithm

    memcpy(*out_buffer, rec->signature_length, SIGNATURE_HASH_LENGTH_LENGTH);
    *out_buffer += SIGNATURE_HASH_LENGTH_LENGTH; // Get past the signature length

    size_t signature_length = byte_to_int(rec->signature_length, SIGNATURE_HASH_LENGTH_LENGTH);
    memcpy(*out_buffer, rec->signature, signature_length);
    *out_buffer += signature_length; // Get past the signature
}

static void serialize_heartbeat(uint8_t **out_buffer, RECORD *rec, RECORD *shadow_rec)
{
    **out_buffer = rec->RES.heartbeat.type;
    *out_buffer += 1; // Get past the type

    memcpy(*out_buffer, rec->RES.heartbeat.payload_length, 2);
    *out_buffer += 2; // Get past the payload length

    size_t payload_length = byte_to_int(shadow_rec->RES.heartbeat.payload_length, 2);
    memcpy(*out_buffer, rec->RES.heartbeat.payload, payload_length);
    *out_buffer += payload_length;

    size_t record_length = byte_to_int(shadow_rec->record_length, 2);
    size_t padding_length = record_length - payload_length - 3;
    memcpy(*out_buffer, rec->RES.heartbeat.padding, padding_length);
    *out_buffer += padding_length;
}

int serialize_record(uint8_t **out_buffer, RECORD *rec, size_t rcvsize, RECORD *shadow_rec)
{
    uint8_t *pointer_to_beginning = *out_buffer;
    assert(rcvsize > RECORD_HEADER_SIZE); // Sanity check to reject records with length lower than the minimum

    memcpy(*out_buffer, rec, RECORD_HEADER_SIZE); // Copy the record header
    *out_buffer += RECORD_HEADER_SIZE; // Get past the Record Header

    if (shadow_rec->content_type == Handshake_REC)
    {
        if (byte_to_int(shadow_rec->epoch, EPOCH_LENGTH) == 0)
        {
            assert(rcvsize >= FRAGMENT_HEADER_SIZE + RECORD_HEADER_SIZE); // Sanity check for the minimum size of the records containing a fragment

            memcpy(*out_buffer, &rec->RES.fragment->handshake_type, sizeof(rec->RES.fragment->handshake_type));
            *out_buffer += sizeof(rec->RES.fragment->handshake_type); // Get past the handshake type

            memcpy(*out_buffer, rec->RES.fragment->handshake_length, sizeof(rec->RES.fragment->handshake_length));
            *out_buffer += sizeof(rec->RES.fragment->handshake_length);

            memcpy(*out_buffer, rec->RES.fragment->message_sequence, sizeof(rec->RES.fragment->message_sequence));
            *out_buffer += sizeof(rec->RES.fragment->message_sequence);

            memcpy(*out_buffer, rec->RES.fragment->fragment_offset, sizeof(rec->RES.fragment->fragment_offset));
            *out_buffer += sizeof(rec->RES.fragment->fragment_offset);

            memcpy(*out_buffer, rec->RES.fragment->fragment_length, sizeof(rec->RES.fragment->fragment_length));
            *out_buffer += sizeof(rec->RES.fragment->fragment_length);

            size_t fragment_length = byte_to_int(shadow_rec->RES.fragment->fragment_length, FRAGMENT_LENGTH_LENGTH);
            size_t handshake_length = byte_to_int(shadow_rec->RES.fragment->handshake_length, HANDSHAKE_LENGTH_LENGTH);
            switch (shadow_rec->RES.fragment->handshake_type)
            {
                case Client_Hello_MSG:
                    serialize_CH(out_buffer, rec->RES.fragment->body.client_hello, fragment_length, shadow_rec->RES.fragment->body.client_hello);
                    break;

                case Client_Key_Exchange_MSG:
                    if (handshake_length != fragment_length)
                    {
                        memcpy(*out_buffer, rec->RES.fragment->body.fragmented->payload, fragment_length);
                        *out_buffer += fragment_length; // Get past the Payload (Fragmented Message)
                    }
                    else
                    {
                        memcpy(*out_buffer, rec->RES.fragment->body.client_key_exchange->client_identity, fragment_length);
                        *out_buffer += fragment_length; // Get past the Client Identity
                    }
                    break;

                case Server_Key_Exchange_MSG:
                    if (handshake_length != fragment_length)
                    {
                        memcpy(*out_buffer, rec->RES.fragment->body.fragmented->payload, fragment_length);
                        *out_buffer += fragment_length; // Get past the payload (Fragmented Message)
                    }
                    else
                    {
                        memcpy(*out_buffer, rec->RES.fragment->body.server_key_exchange->payload, fragment_length);
                        *out_buffer += fragment_length; // Get past the payload
                    }
                    break;

                case Hello_Verify_Request_MSG:
                    serialize_HVR(out_buffer, rec->RES.fragment->body.hello_verify_request, fragment_length, shadow_rec->RES.fragment->body.hello_verify_request);
                    break;

                case Server_Hello_MSG:
                    if (handshake_length != fragment_length)
                    {
                        printf("\nfrag length:%zu\n", fragment_length);
                        memcpy(*out_buffer, rec->RES.fragment->body.fragmented->payload, fragment_length);
                        *out_buffer += fragment_length; // Get past the payload (Fragmented Message)
                    }
                    else
                    {
                        serialize_SH(out_buffer, rec->RES.fragment->body.server_hello, fragment_length, shadow_rec->RES.fragment->body.server_hello);
                    }
                    break;

                case New_Session_ticket:
                    memcpy(*out_buffer, rec->RES.fragment->body.new_session_ticket->payload, fragment_length);
                    *out_buffer += fragment_length; // Get past the payload
                    break;

                case Certificate_MSG:
                    if (fragment_length != handshake_length)
                    {
                        memcpy(*out_buffer, rec->RES.fragment->body.fragmented->payload, fragment_length);
                        *out_buffer += fragment_length; // Get past the payload (Fragmented Message)
                    }
                    else
                    {
                        serialize_CE(out_buffer, rec->RES.fragment->body.certificate, fragment_length, shadow_rec->RES.fragment->body.certificate);
                    }

                    break;

                case Certificate_Verify_MSG:
                    serialize_CEV(out_buffer, rec->RES.fragment->body.certificate_verify, fragment_length, shadow_rec->RES.fragment->body.certificate_verify);
                    break;

                case Certificate_Request_MSG:
                    serialize_CER(out_buffer, rec->RES.fragment->body.certificate_request, fragment_length, shadow_rec->RES.fragment->body.certificate_request);
                    // memcpy(*out_buffer, rec->RES.fragment->body.certificate_request->payload, fragment_length);
                    // *out_buffer += fragment_length; // Get past the payload
                    break;

                case Server_Hello_Done_MSG:
                    // Since Server Hello Done does not contain any message, we do not have to do anything here
                    break;
            }
        }
        else
        {
            size_t record_length = byte_to_int(shadow_rec->record_length, RECORD_LENGTH_LENGTH);
            memcpy(*out_buffer, rec->RES.fragment->encrypted_content, record_length);
            *out_buffer += record_length; // Get past the encrypted content
        }
    }
    else if (shadow_rec->content_type == Change_Cipher_Spec_REC)
    {
        **out_buffer = rec->RES.change_cipher_spec.ccs_msg;
        *out_buffer += 1; // Get past the CCS MSG
    }
    else if (shadow_rec->content_type == Application_Data)
    {
        size_t record_length = byte_to_int(shadow_rec->record_length, RECORD_LENGTH_LENGTH);
        memcpy(*out_buffer, rec->RES.application_data.encrypted_message, record_length);
        *out_buffer += record_length; // Get past the encrypted message
    }
    else if (shadow_rec->content_type == Alert_REC)
    {
        **out_buffer = rec->RES.alert.level;
        *out_buffer += 1; // Get past the Alert Level
        **out_buffer = rec->RES.alert.desc;
        *out_buffer += 1; // Get past the Alert Desc
    }
    else if (shadow_rec->content_type == Heartbeat_REC)
    {
        serialize_heartbeat(out_buffer, rec, shadow_rec);
    }

    return *out_buffer - pointer_to_beginning;
}

static void copy_record_header(RECORD *dest_rec, RECORD *src_rec)
{
    dest_rec->content_type = src_rec->content_type;
    memcpy(dest_rec->record_version, src_rec->record_version, RECORD_VERSION_LENGTH);
    memcpy(dest_rec->epoch, src_rec->epoch, EPOCH_LENGTH);
    memcpy(dest_rec->sequence_number, src_rec->sequence_number, RECORD_SEQ_NUMBER_LENGTH);
    memcpy(dest_rec->record_length, src_rec->record_length, RECORD_LENGTH_LENGTH);
}
static void copy_fragment_header(FRAGMENT *dest_frag, FRAGMENT *src_frag)
{
    dest_frag->handshake_type = src_frag->handshake_type;
    memcpy(dest_frag->handshake_length, src_frag->handshake_length, HANDSHAKE_LENGTH_LENGTH);
    memcpy(dest_frag->message_sequence, src_frag->message_sequence, MESSAGE_SEQ_LENGTH);
    memcpy(dest_frag->fragment_offset, src_frag->fragment_offset, FRAGMENT_OFFSET_LENGTH);
    memcpy(dest_frag->fragment_length, src_frag->fragment_length, FRAGMENT_LENGTH_LENGTH);
}

static void fragment_DTLS_message(RECORD input_record, RECORD *fragmented_records)
{
    size_t inp_fragment_length = byte_to_int(input_record.RES.fragment->fragment_length, FRAGMENT_LENGTH_LENGTH);
    size_t frag1_size = inp_fragment_length / 2;
    size_t frag2_size = inp_fragment_length - frag1_size;

    fragmented_records[0].RES.fragment = malloc(sizeof(FRAGMENT));
    fragmented_records[0].RES.fragment->body.fragmented = malloc(sizeof(FRAGMENTED));
    fragmented_records[0].RES.fragment->body.fragmented->payload = malloc(frag1_size);


    fragmented_records[1].RES.fragment = malloc(sizeof(FRAGMENT));
    fragmented_records[1].RES.fragment->body.fragmented = malloc(sizeof(FRAGMENTED));
    fragmented_records[1].RES.fragment->body.fragmented->payload = malloc(frag2_size);
    copy_record_header(&fragmented_records[0], &input_record);
    copy_record_header(&fragmented_records[1], &input_record);
    copy_fragment_header(fragmented_records[0].RES.fragment, input_record.RES.fragment);
    copy_fragment_header(fragmented_records[1].RES.fragment, input_record.RES.fragment);

    int_to_uint16(fragmented_records[0].record_length, frag1_size + FRAGMENT_HEADER_SIZE);
    int_to_uint16(fragmented_records[1].record_length,  frag2_size + FRAGMENT_HEADER_SIZE);

    int_to_uint48(fragmented_records[1].sequence_number, (byte_to_int(&input_record.sequence_number[2], 4)) + 1);

    int_to_uint24(fragmented_records[0].RES.fragment->fragment_length, frag1_size);
    int_to_uint24(fragmented_records[1].RES.fragment->fragment_length, frag2_size);

    int_to_uint24(fragmented_records[1].RES.fragment->fragment_offset, frag1_size);

    memcpy(fragmented_records[0].RES.fragment->body.fragmented->payload, input_record.payload + FRAGMENT_HEADER_SIZE, frag1_size);
    memcpy(fragmented_records[1].RES.fragment->body.fragmented->payload, input_record.payload + FRAGMENT_HEADER_SIZE + frag1_size, frag2_size);
}

void determine_record_content(RECORD *rec, char* record_content, size_t record_content_size, bool is_input)
{
    char *content = malloc(record_content_size);

    int remaining_space = record_content_size - 1;

    uint64_t epoch = klee_get_valuell(byte_to_int(rec->epoch, sizeof(rec->epoch)));
    uint64_t record_sequence_number = klee_get_valuell(byte_to_int(rec->sequence_number, sizeof(rec->sequence_number)));
    switch (rec->content_type)
    {
        case Handshake_REC:
            if (is_input)
                snprintf(content, remaining_space, "[input] Handshake | HType:%"PRId32" - ", klee_get_value_i32(rec->RES.fragment->handshake_type));
            else
            {
                int32_t handshake_type = klee_get_value_i32(rec->RES.fragment->handshake_type);                
                uint64_t message_sequence_number = klee_get_valuell(byte_to_int(rec->RES.fragment->message_sequence, sizeof(rec->RES.fragment->message_sequence)));
                snprintf(content, remaining_space, "[output] Handshake | HType:%"PRId32" | Epoch:%"PRIu64" | RSeq_num:%"PRIu64" | MSeq_num:%"PRIu64"", 
                        handshake_type, epoch, record_sequence_number, message_sequence_number);
            }                
            break;
        case Change_Cipher_Spec_REC:
            if (is_input)
                snprintf(content, remaining_space, "[input] CCS - ");
            else
            {
                snprintf(content, remaining_space, "[output] CCS | Epoch:%"PRIu64" | RSeq_num:%"PRIu64"", epoch, record_sequence_number);
            }
            break;
        case Alert_REC:
            if (is_input)
                snprintf(content, remaining_space,"[input] Alert - ");
            else
            {
                int32_t alert_level = klee_get_value_i32(rec->RES.alert.level);
                int32_t alert_desc = klee_get_value_i32(rec->RES.alert.desc);
                snprintf(content, remaining_space, "[output] Alert | Epoch:%"PRIu64" | RSeq_num:%"PRIu64" | Level:%"PRId32" | Desc:%"PRId32"", epoch, record_sequence_number, alert_level, alert_desc);
            }                
            break;
        case Application_Data:
            if (is_input)
                snprintf(content, remaining_space, "[input] App_data - ");
            else
            {
                snprintf(content, remaining_space, "[output] App_data | Epoch:%"PRIu64" | RSeq_num:%"PRIu64"", epoch, record_sequence_number);
            }
            break;
        default:
            fprintf(stderr, "Content Type could not be determined!\n\n");
            exit(EXIT_FAILURE);
            break;
    }
    strncat(record_content, content, record_content_size);
    free(content);
}

int64_t original_sequence_number = -1;

/*
** We handle different aspects of fragmentation by calling handle_DTLS_fragmentation.
** Each message will be fragmented into two messages. (fragmented_records).
** The sequence numbers of each records for fragmented messages will be updated.
** The sequence numbers for subsequence records will be updated.
*/

size_t handle_DTLS_fragmentation(const uint8_t *datagram, size_t datagram_size, uint8_t *out_datagram,
                                 QUEUE *queue, bool is_client_originated, int state_to_check)
{

    RECORD fragmented_records[2];

    size_t off = 0;

    int8_t server_states[] = {0, 2, 8, 9, 10, 11, 12, 15};
    size_t new_datagram_size = datagram_size;

    static uint8_t frag1_buffer[1400];
    static uint8_t frag2_buffer[1400];
    uint8_t  *pointer_to_frag1;
    uint8_t  *pointer_to_frag2;
    pointer_to_frag1 = frag1_buffer;
    pointer_to_frag2 = frag2_buffer;

    while (off != datagram_size)
    {
        RECORD input_record;

        int record_length = parse_record(datagram, &input_record, &off, datagram_size, is_client_originated);

        // Check if it is the message we want to fragment
        if (input_record.content_type == Handshake_REC &&
            input_record.RES.fragment->handshake_type == state_to_message_type(state_to_check))
        {
            original_sequence_number = byte_to_int(input_record.sequence_number, 6);

            // Main function for fragmenting two messages
            fragment_DTLS_message(input_record, fragmented_records);

            // serialize the both fragments to temporary buffers and put them in the respective queue
            int frag1_size = serialize_record( &pointer_to_frag1, &fragmented_records[0], datagram_size, &fragmented_records[0]);
            int frag2_size =serialize_record( &pointer_to_frag2, &fragmented_records[1], datagram_size, &fragmented_records[1]);

            // Put the first fragment into the queue
            Element *frag1_element = malloc(sizeof(*frag1_element));
            frag1_element->buffer_size = frag1_size;
            frag1_element->buffer_address = malloc(frag1_element->buffer_size);
            memcpy(frag1_element->buffer_address, frag1_buffer, frag1_element->buffer_size);
            enqueue(queue, frag1_element);

            // Put the second fragment into the queue
            Element *frag2_element = malloc(sizeof(*frag2_element));
            frag2_element->buffer_size = frag2_size;
            frag2_element->buffer_address = malloc(frag2_element->buffer_size);
            memcpy(frag2_element->buffer_address, frag2_buffer, frag2_element->buffer_size);
            enqueue(queue, frag2_element);


            // Updating the datagram size
            new_datagram_size = datagram_size - record_length;
        }
        else
        {
            // Update the seuqence numbers for the subsequent records
            if (is_client_originated == is_exist(state_to_check, server_states) && original_sequence_number > 0)
            {
                uint64_t current_sequence_number = byte_to_int(input_record.sequence_number, 6);
                if (current_sequence_number >= original_sequence_number)
                {
                    int_to_uint48(input_record.sequence_number, (byte_to_int(&input_record.sequence_number[2], 4)) + 1);
                }
            }
            serialize_record(&out_datagram, &input_record, datagram_size, &input_record);
        }
    }
    // We return the new datagram size
    return new_datagram_size;
}