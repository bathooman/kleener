#ifndef HELPER_H
#define HELPER_H

#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <memory.h>
#include <sys/socket.h>
#include <stdarg.h>

#define ANSI_COLOR_RED     "\x1b[31m"
#define ANSI_COLOR_GREEN   "\x1b[32m"
#define ANSI_COLOR_YELLOW  "\x1b[33m"
#define ANSI_COLOR_BLUE    "\x1b[34m"
#define ANSI_COLOR_MAGENTA "\x1b[35m"
#define ANSI_COLOR_CYAN    "\x1b[36m"
#define ANSI_COLOR_RESET   "\x1b[0m"

#define OR |
#define AND &


typedef struct
{
    size_t buffer_size;
    uint8_t* buffer_address;
}Element;

typedef struct
{
    unsigned capacity,front, rear, size;
    Element **elem;
}QUEUE;

typedef enum{
    CLIENT=0, 
    SERVER=1, 
    NONE=2
    }SIDE;

typedef int8_t STATE;

size_t load_record(char *file_name, uint8_t *buf, uint16_t buff_size);
void write_record_to_file(char *name, uint8_t *buf, size_t size);
void dump_record(const void *buf, size_t size);
uint64_t byte_to_int(const uint8_t input[], size_t size);
int int_to_uint8(unsigned char *field, uint8_t value);
int int_to_uint16(uint8_t *field, uint16_t value);
int int_to_uint24(unsigned char *field, uint32_t value);
int int_to_uint32(unsigned char *field, uint32_t value);
int int_to_uint48(unsigned char *field, uint64_t value);
int int_to_uint64(unsigned char *field, uint64_t value);
QUEUE *createQueue (unsigned capacity);
bool isFull (QUEUE *queue);
bool isEmpty (QUEUE *queue);
void enqueue (QUEUE *queue, Element *elem);
Element *dequeue (QUEUE *queue);
bool is_exist(int element, int8_t *list);
void kleener_log(const char *text, const char *file_name, const int line_number, int level, ...);
void kleener_make_symbolic(void *addr, size_t nbytes, const char *name);
void kleener_assert(const char *message);
SIDE which_side_checked(const char *state_env);
#endif //DTLSRECORDS_HELPER_H