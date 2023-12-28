//
// Created by hooman on 2022-02-18.
//
#include "klee/Support/Protocols/helper.h"
#include "klee/klee.h"
#include <stdio.h>
#include <memory.h>
#include <errno.h>
#include <stdlib.h>
#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <sys/socket.h>
#include <stdarg.h>
#include <assert.h>

size_t load_record(char *file_name, uint8_t *buf, uint16_t buff_size)
{
    FILE *f = fopen(file_name, "rb");
    if (f == NULL)
    {
        perror("Oops: ");
        return -1;
    }
    size_t size = fread(buf, sizeof *buf, buff_size, f);
    if (ferror(f) != 0)
    {
        perror("Oops: ");
        return -1;
    }
    return size;
}

void write_record_to_file(char *name, uint8_t *buf, size_t size)
{
    FILE *f = fopen(name, "wb");
    fwrite(buf, 1, size, f);
}

void dump_record(const void *buf, size_t size)
{
    const unsigned char *byte;
    for (byte = buf; size--; ++byte)
    {
        printf("%02X", *byte);
    }
    putchar('\n');
}

uint64_t byte_to_int(const uint8_t input[], size_t size)
{
    if (size == 0)
        return 0;

    uint64_t result = 0;

    for (size_t i = size; i > 0; i--)
    {
        result |= (uint64_t)input[i - 1] << (size - i) * 8;
    }
    return result;
}

int int_to_uint8(unsigned char *field, uint8_t value)
{
    field[0] = value & 0xff;
    return 1;
}

int int_to_uint16(uint8_t *field, uint16_t value)
{
    field[0] = (value >> 8) & 0xff;
    field[1] = value & 0xff;
    return 2;
}

int int_to_uint24(unsigned char *field, uint32_t value)
{
    field[0] = (value >> 16) & 0xff;
    field[1] = (value >> 8) & 0xff;
    field[2] = value & 0xff;
    return 3;
}

int int_to_uint32(unsigned char *field, uint32_t value)
{
    field[0] = (value >> 24) & 0xff;
    field[1] = (value >> 16) & 0xff;
    field[2] = (value >> 8) & 0xff;
    field[3] = value & 0xff;
    return 4;
}

int int_to_uint48(unsigned char *field, uint64_t value)
{
    field[0] = (value >> 40) & 0xff;
    field[1] = (value >> 32) & 0xff;
    field[2] = (value >> 24) & 0xff;
    field[3] = (value >> 16) & 0xff;
    field[4] = (value >> 8) & 0xff;
    field[5] = value & 0xff;
    return 6;
}

int int_to_uint64(unsigned char *field, uint64_t value)
{
    field[0] = (value >> 56) & 0xff;
    field[1] = (value >> 48) & 0xff;
    field[2] = (value >> 40) & 0xff;
    field[3] = (value >> 32) & 0xff;
    field[4] = (value >> 24) & 0xff;
    field[5] = (value >> 16) & 0xff;
    field[6] = (value >> 8) & 0xff;
    field[7] = value & 0xff;
    return 8;
}
void kleener_log(const char *text, const char *file_name, const int line_number, int level, ...)
{
    va_list args;
    va_start(args, level);

    switch (level)
    {
    case 1:
        printf(ANSI_COLOR_GREEN "\n[KLEENER: %s:%d]: ", file_name, line_number);
        vprintf(text, args);
        printf(ANSI_COLOR_RESET "\n");
        printf("\n");        
        break;
    
    default:
        break;
    }
    va_end(args);


}
QUEUE *createQueue (unsigned capacity)
{
    QUEUE *queue = (QUEUE *) malloc(sizeof(QUEUE));
    queue->capacity = capacity;
    queue->front = queue->size = 0;
    queue->rear = capacity - 1;
    queue->elem = malloc(queue->capacity * sizeof(*queue->elem));

    return queue;
}

bool isFull (QUEUE *queue)
{
    return (queue->size == queue->capacity);
}

bool isEmpty (QUEUE *queue)
{
    return (queue->size == 0);
}

void enqueue (QUEUE *queue, Element *elem)
{
    if (isFull(queue))
    {
        puts("Queue is Full!");
        return;
    }
    queue->rear = (queue->rear + 1) % queue->capacity;
    queue->elem[queue->rear] = elem;
    queue->size = queue->size + 1;
}

Element *dequeue (QUEUE *queue)
{
    if (isEmpty(queue))
    {
        puts("Queue is Empty!");
        return NULL;
    }
    Element *ret = queue->elem[queue->front];
    queue->front = (queue->front + 1) % queue->capacity;
    queue->size = queue->size - 1;
    return ret;
}

bool is_exist(int element, int8_t *list)
{
	for (int i = 0; i < sizeof(list); i++)
	{
		if (element == list[i])
			return true;
	}
	return false;
}

void kleener_make_symbolic(void *addr, size_t nbytes, const char *name)
{
    uint8_t *sym_buf = malloc(nbytes);
    klee_make_symbolic(sym_buf, nbytes, name);

    memcpy(addr, sym_buf, nbytes);
}

void kleener_assert(const char *message)
{
    assert(0 && message);
}

SIDE which_side_checked(const char *state_env)
{
	if ((strcmp(state_env, "server") == 0) || (strcmp(state_env, "SERVER") == 0))
		return SERVER;
	else if ((strcmp(state_env, "client") == 0) || (strcmp(state_env, "CLIENT") == 0))
		return CLIENT;
	else
	{
		printf("\n[Model-log] No side will be checked\n");
		return NONE;
	}
}