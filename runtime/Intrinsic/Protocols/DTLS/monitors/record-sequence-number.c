#include "klee/Protocols/dtls/dtls_monitors.h"
#include "klee/Protocols/dtls/dtls_records.h"
#include "klee/Support/Protocols/helper.h"
#include "klee/klee.h"
#include <assert.h>

/* Requirement (DTLS RFC 6347 Section 4.1.2.6):
For each received record, the receiver MUST verify that the record 
contains a sequence number thatdoes not duplicate the sequence number
of any other record received during the life of this session.
Duplicates are rejected through the use of a sliding receive window. 
A window size of 64 is preferred and SHOULD be employed
as the default. The "right" edge of the window represents the
highest validated sequence number value received on this session.
Records that contain sequence numbers lower than the "left" edge
of the window are rejected. If the received record falls within the
window and is new, or if the packet is to the right of the window,
then the receiver proceeds to MAC verification.
*/

/* Discard Requirement (DTLS RFC 6347 Section 4.1.2.7):
In general, invalid records SHOULD be silently discarded, 
thus preserving the association; however, an error MAY be 
logged for diagnostic purposes.
*/

#define STRING_FIXED_SIZE 50
#define MAX_RECORD_COUNT 10
#define VALID_WINDOW_SIZE 0x40
#define SEQUENCE_NUMBER_LENGTH 6

// Local state values
#define INITIAL 0
#define MORE_RECORDS_RECEIVED 1
#define DONE 2

static STATE local_state = INITIAL; 
static size_t received_records_counter = 0; // Keeps the number of received records
static uint8_t sequence_numbers[MAX_RECORD_COUNT][SEQUENCE_NUMBER_LENGTH]; // Keeps the sequence number of received records
static uint64_t *right_edges = NULL;

/* 
* This boolean function checks if input a is either greater than input b or
* if not, it is in the range of a win_size.
*/
static bool is_in_window_or_after(uint64_t a, uint64_t b, uint64_t win_size)
{
  return (a > b) | ((a < b) & ((b < win_size) | ((b >= win_size) & (a >= b - win_size))));
}

/*
* This function assumes the output to be equal to the maximum of
* a and b.
*/
static void max_symbolic(uint64_t output, uint64_t a, uint64_t b)
{
  klee_assume(
      ((a >= b) & (output == a)) | ((a < b) & (output == b)));
}


void is_record_sequence_number_valid_server(RECORD *record, bool is_record_client_generated)
{
    char symbolic_variable_name[STRING_FIXED_SIZE];
    
    if (is_record_client_generated)
    {
        switch (local_state)
        {
        case INITIAL:
            // We only check this requirement for records for which the epoch is zero
            // This indirectly ensures that the content of the message is not encrypted 
            if (byte_to_int(record->epoch, sizeof(record->epoch)) == 0)
            {
                // Make the sequence number for the first received record symbolic
                sprintf(symbolic_variable_name, "sequence_number:%zu", received_records_counter);
                kleener_make_symbolic(sequence_numbers[received_records_counter], sizeof(record->sequence_number), symbolic_variable_name);
                memcpy(record->sequence_number, sequence_numbers[received_records_counter], sizeof(record->sequence_number));

                //Allocate memory for the right edge of the first received record and make it symbolic
                right_edges = malloc((received_records_counter + 1) * sizeof(uint64_t));
                kleener_make_symbolic(&right_edges[received_records_counter], sizeof(uint64_t), "right_edge[0]");

                // Assign the right edge (highest validated sequence number) of the first recevived record 
                // to be equal to the sequence number of the first received record
                right_edges[received_records_counter] = byte_to_int(sequence_numbers[received_records_counter], SEQUENCE_NUMBER_LENGTH); 

                local_state = MORE_RECORDS_RECEIVED;
                received_records_counter++;
            }            
            break;

        case MORE_RECORDS_RECEIVED:
            // This indirectly ensures that the content of the message is not encrypted
            if (byte_to_int(record->epoch, sizeof(record->epoch)) == 0)
            {
                // Make the sequence number for the subsequent messages symbolic                
                sprintf(symbolic_variable_name, "sequence_number:%zu", received_records_counter);
                kleener_make_symbolic(sequence_numbers[received_records_counter], sizeof(record->sequence_number), symbolic_variable_name);
                memcpy(record->sequence_number, sequence_numbers[received_records_counter], sizeof(record->sequence_number));
                
                // Allocate more memory for the right edge of the newly received record and make it symbolic
                right_edges = realloc( right_edges, (received_records_counter + 1) * sizeof(uint64_t));
                sprintf(symbolic_variable_name, "right_edge[%zu]", received_records_counter);
                kleener_make_symbolic(&right_edges[received_records_counter], sizeof(uint64_t), symbolic_variable_name);
                
                // Assuming the right edge of the received record to be the maximum of the sequence number 
                // of the recieved record and the previous record's right edge
                max_symbolic(right_edges[received_records_counter], byte_to_int(sequence_numbers[received_records_counter], SEQUENCE_NUMBER_LENGTH), right_edges[received_records_counter-1]);

                // We assume that the sequence number of the newly received record is not valid
                // based on the defined VALID_WINDOW_SIZE
                klee_assume(!is_in_window_or_after(byte_to_int(sequence_numbers[received_records_counter], SEQUENCE_NUMBER_LENGTH), right_edges[received_records_counter - 1], VALID_WINDOW_SIZE)); 
                received_records_counter++;                            
            }
            // If the subsequent message is encrypted, we go to the Done State
            else
            {
                local_state = DONE;
            }
            break;
            
        default:
            break;
        }
    }
    
    else if (!is_record_client_generated && local_state == DONE)
    {
        // If more than one record is received and we had response by the client after invalid sequence numbers,
        // We assert(0)
        if (received_records_counter > 1 && record->content_type != Alert_REC)
            assert(0 && "record_sequence_number");
    }
}

void is_record_sequence_number_valid_client(RECORD *record, bool is_record_client_generated)
{
    char symbolic_variable_name[STRING_FIXED_SIZE];
    
    if (!is_record_client_generated)
    {
        switch (local_state)
        {
        case INITIAL:
            if (byte_to_int(record->epoch, sizeof(record->epoch)) == 0)
            {
                sprintf(symbolic_variable_name, "sequence_number:%zu", received_records_counter);
                kleener_make_symbolic(sequence_numbers[received_records_counter], sizeof(record->sequence_number), symbolic_variable_name);
                memcpy(record->sequence_number, sequence_numbers[received_records_counter], sizeof(record->sequence_number));
                right_edges = malloc((received_records_counter + 1) * sizeof(uint64_t));
                kleener_make_symbolic(&right_edges[received_records_counter], sizeof(uint64_t), "right_edge[0]");

                right_edges[received_records_counter] = byte_to_int(sequence_numbers[received_records_counter], SEQUENCE_NUMBER_LENGTH); 
                local_state = MORE_RECORDS_RECEIVED;
                received_records_counter++;
            }
            
            break;

        case MORE_RECORDS_RECEIVED:
            if (byte_to_int(record->epoch, sizeof(record->epoch)) == 0)
            {
                sprintf(symbolic_variable_name, "sequence_number:%zu", received_records_counter);
                kleener_make_symbolic(sequence_numbers[received_records_counter], sizeof(record->sequence_number), symbolic_variable_name);
                memcpy(record->sequence_number, sequence_numbers[received_records_counter], sizeof(record->sequence_number));
                
                right_edges = realloc( right_edges, (received_records_counter + 1) * sizeof(uint64_t));

                sprintf(symbolic_variable_name, "right_edge[%zu]", received_records_counter);
                kleener_make_symbolic(&right_edges[received_records_counter], sizeof(uint64_t), symbolic_variable_name);
                
                
                max_symbolic(right_edges[received_records_counter], byte_to_int(sequence_numbers[received_records_counter], SEQUENCE_NUMBER_LENGTH), right_edges[received_records_counter-1]);
                klee_assume(!is_in_window_or_after(byte_to_int(sequence_numbers[received_records_counter], SEQUENCE_NUMBER_LENGTH), right_edges[received_records_counter - 1], VALID_WINDOW_SIZE)); 
                received_records_counter++;  
            }    
            else
            {
                local_state = DONE;
            }                                
            break;

        default:
            break;
        }
    }
    else if (is_record_client_generated && local_state == DONE)
    {
        if (received_records_counter > 1 && record->content_type != Alert_REC)
            assert(0 && "record_sequence_number");
    }
}

