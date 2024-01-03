#include "klee/Protocols/dtls/dtls_socket_model.h"
#include "klee/Protocols/dtls/dtls_records.h"
#include "klee/Protocols/dtls/dtls_states.h"
#include "klee/Protocols/dtls/dtls_monitors.h"
#include "klee/Support/Protocols/datagram.h"
#include "klee/Support/Protocols/helper.h"
#include <stdio.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <klee/klee.h>
#include <memory.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <stdlib.h>
#include <stdbool.h>

static QUEUE *recv_by_server; // The queue that contains packets sent by the client
static QUEUE *recv_by_client; //The queue that contains packets sent by the server

static bool isfirst_server= true; // Is the the first time that server receives a packet
static bool isfirst_client= true; // // Is the the first time that client receives a packet

static int server_fd = 0; // File descriptor for the server
static int client_fd = 0; // File descriptor for the client

// Global Server/Client address and length that is used for modeling the socket calls
static struct sockaddr *server_addr;
static socklen_t server_addr_len;
static struct sockaddr_in *client_addr;
static socklen_t client_addr_len;

// Server Port
/* We need to pass the server port as an environment variable to be able to distinguish between the 
// FD for the server and the client */
static int server_port = -1;


static int experiment;
static int state_to_check;
static MONITOR dtls_monitor;
static bool chosen_cipher;
static bool is_first_time_called = true;
static bool is_fragmented = false;

static void set_run_parameters(int *experiment, int *state_to_check, MONITOR *dtls_monitor, bool *chosen_cipher, bool *is_fragmented)
{
	SIDE side_to_check;
	const char *envstate = getenv("KLEE_SYMBOLIC_EXPERIMENT");
	if (envstate == NULL)
	{
		printf("\n[Model-log] Environment Variable KLEE_SYMBOLIC_EXPERIMENT has not been set\n");
		_exit(-1);
	}
	*experiment = atoi(envstate);

	const char *chcipher = getenv("CHOSEN_CIPHER");
	if (strcmp(chcipher, "psk") == 0)
	{
		*chosen_cipher = 0;
	}
	else if (strcmp(chcipher, "ecc") == 0)
	{
		*chosen_cipher = 1;
	}
	else
	{
		printf("\n[Model-log] No Valid Cipher: We choose PSK\n");
		*chosen_cipher = 0;
	}

	const char *state_env = getenv("STATE_TO_CHECK");
	if (state_env == NULL)
	{
		printf("\n[Model-log] Environment Variable STATE_TO_CHECK has not been set\n");
		_exit(-1);
	}
	side_to_check = which_side_checked(state_env);

	dtls_monitor->handle = set_monitor_handle(*experiment, side_to_check);
	if (dtls_monitor->handle == NULL)
	{
		printf("\n[Model-log] No valid experiment is set (Normal Execution)\n");

	}
	dtls_monitor->valid_states = set_monitor_valid_states(*experiment, side_to_check);

	*state_to_check = determine_state_to_check(dtls_monitor->valid_states, side_to_check, *chosen_cipher);
	if (*state_to_check == -1)
	{
		printf("\n[Model-log] No Valid State to Check\n");
	}

	const char *isfragmented = getenv("IS_FRAGMENTED");
	if (isfragmented == NULL)
	{
		printf("\n[Model-log] Environment Variable IS_FRAGMENTED has not been set\n");
		_exit(-1);
	}

	*is_fragmented = atoi(isfragmented);
}

int DTLS_bind_model(int sockfd, const struct sockaddr *myaddr, socklen_t addrlen)
{	
	
    int ret = syscall(SYS_bind, sockfd, myaddr, addrlen);

	// We create a queue with the capacity of 100 messages for both the client and the server
	// This queue is used to imitate sending and receiving data over socket calls
	recv_by_server = createQueue(100);
	recv_by_client = createQueue(100);

	const char *envstate = getenv("SERVER_PORT");
	if (envstate == NULL)
	{
		printf("\n[Model-log] Environment Variable SERVER_PORT has not been set\n");
		_exit(-1);
	}
	server_port = atoi(envstate);


	// determining the port that is used in the call
	struct sockaddr_in *address = (struct sockaddr_in*)myaddr;
	uint16_t port = htons(address->sin_port);
	

	if (port == server_port)
	{
		server_fd = sockfd;
	}
	else
	{
		client_fd = sockfd;
	}

	if (is_first_time_called)
	{
		set_run_parameters(&experiment, &state_to_check, &dtls_monitor, &chosen_cipher, &is_fragmented);
		is_first_time_called = false;
	}
	return ret;
}


ssize_t DTLS_recvfrom_model(int __fd, void *__buf, size_t __n, int __flags,
				 struct sockaddr *__addr, socklen_t *__addr_len)
{
    
	if (isfirst_server && server_fd == __fd)
	{
		Element *item;
		// puts("\n\nisfirst_server && server_fd == __fd\n\n");
		// MSG_DONTWAIT |
		long recvlen = syscall(SYS_recvfrom, __fd, __buf, __n, __flags, __addr , __addr_len);
	
		if (recvlen < 0)
		{
			printf("\n[Model-log] recvfrom() failed\n");
			return recvlen;
		}
		if (!isEmpty(recv_by_server))
		{
			item = dequeue(recv_by_server);
			__n = item->buffer_size;
		}
		else
		{
			printf("\n[Model-log] server queue is empty!\n");
			return -1;
		}

		
		// Storing the address for the server and the length of it to use in subsequent calls to recvfrom
		server_addr_len = *__addr_len;
		server_addr = malloc(*__addr_len);
		memcpy(server_addr, __addr, *__addr_len);
		
		handle_DTLS_datagram(item->buffer_address, item->buffer_size, __buf, 1, dtls_monitor.handle, state_to_check);


		// char file_name[30];
		// sprintf(file_name, "rec:%lu", __n);
		// write_record_to_file(file_name, __buf, __n);
		// klee_assert(memcmp(__buf, item->buffer_address, item->buffer_size) == 0);
		

		isfirst_server = false;
		free(item->buffer_address);
		free(item);
	}
	else if (isfirst_client && server_fd != __fd)
	{
		Element *item;
		// puts("\n\nisfirst_client && server_fd != __fd\n\n");
		long recvlen = syscall(SYS_recvfrom, __fd, __buf, __n, __flags, __addr, __addr_len);
	
		if (recvlen < 0)
		{
			printf("\n[Model-log] recvfrom() failed\n");
			return recvlen;
		}
		if (!isEmpty(recv_by_client))
		{
			item = dequeue(recv_by_client);
			__n = item->buffer_size;
		}
		else
		{
			printf("\n[Model-log] client queue is empty!\n");
			return -1;
		}
		
		
		// Storing the address for the client and the length of it to use in subsequent calls to recvfrom
		client_addr_len = *__addr_len;
		client_addr = malloc(*__addr_len);
		memcpy(client_addr, __addr, *__addr_len);


		handle_DTLS_datagram(item->buffer_address, item->buffer_size, __buf, 0, dtls_monitor.handle, state_to_check);

		// klee_assert(memcmp(__buf, item->buffer_address, item->buffer_size) == 0);
		// char file_name[30];
		// sprintf(file_name, "rec:%lu", __n);
		// write_record_to_file(file_name, __buf, __n);

		isfirst_client = false;
		free(item->buffer_address);
		free(item);
		
	}
	else if (!isfirst_server && server_fd == __fd)
	{
		Element *item;
		// puts("\n\n!isfirst_server && server_fd == __fd\n\n");
		if (!isEmpty(recv_by_server))
		{
			item = dequeue(recv_by_server);
			__n = item->buffer_size;
		}
		else
		{
			printf("\n[Model-log] server queue is empty!\n");
			return -1;
		}
				

		// Use the old values for __addr and __addr_len since we are not calling the syscall
		memcpy(__addr, server_addr, server_addr_len);
		*__addr_len = server_addr_len;
		
		// char file_name[30];
		// sprintf(file_name, "rec:%lu-before", __n);
		// write_record_to_file(file_name, item->buffer_address, __n);
		
		handle_DTLS_datagram(item->buffer_address, item->buffer_size, __buf, 1, dtls_monitor.handle, state_to_check);
	
		// klee_assert(memcmp(__buf, item->buffer_address, item->buffer_size) == 0);

		free(item->buffer_address);
		free(item);
	}
	else if (!isfirst_client && server_fd != __fd)
	{
		Element *item;
		// puts("\n\n!isfirst_client && server_fd != __fd\n\n");

		if (!isEmpty(recv_by_client))
		{
			item = dequeue(recv_by_client);
			__n = item->buffer_size;
		}
		else
		{
			printf("\n[Model-log] client queue is empty!\n");
			return -1;
		}
		

		// Use the old values for __addr and __addr_len since we are not calling the syscall
		memcpy(__addr, client_addr, client_addr_len);
		*__addr_len = client_addr_len;


		handle_DTLS_datagram(item->buffer_address, item->buffer_size, __buf, 0, dtls_monitor.handle, state_to_check);
		
		// klee_assert(memcmp(__buf, item->buffer_address, item->buffer_size) == 0);
		// char file_name[30];
		// sprintf(file_name, "rec:%lu", __n);
		// write_record_to_file(file_name, __buf, __n);

		free(item->buffer_address);
		free(item);
	}
	return __n;
}

ssize_t DTLS_sendto_model(int __fd, const void *__buf, size_t __n,
			   int __flags, const struct sockaddr *__addr,
			   socklen_t __addr_len)
{
    uint8_t temp_buf[1024];

	int ret = syscall(SYS_sendto, __fd, __buf, __n, __flags, __addr, __addr_len);
	if (ret < 0)
	{
		printf("\n[Model-log] sendto() failed\n");
	}

	if (__fd == server_fd)
	{
		if (is_fragmented)
		{
			__n = handle_DTLS_fragmentation(__buf, __n, temp_buf, recv_by_client, 0, state_to_check);
			if (__n > 0)
			{
				Element *queue_element = malloc(sizeof(*queue_element));
				queue_element->buffer_size = __n;
				queue_element->buffer_address = malloc(queue_element->buffer_size);
				memcpy(queue_element->buffer_address, temp_buf, queue_element->buffer_size);
				enqueue(recv_by_client, queue_element);
			}
			
		}
		else
		{
			Element *queue_element = malloc(sizeof(*queue_element));
			queue_element->buffer_size = __n;
			queue_element->buffer_address = malloc(queue_element->buffer_size);
			memcpy(queue_element->buffer_address, __buf, queue_element->buffer_size);
			
			enqueue(recv_by_client, queue_element);
			
		}
		
	}
	else
	{
		if (is_fragmented)
		{
			__n = handle_DTLS_fragmentation(__buf, __n, temp_buf, recv_by_server, 1, state_to_check);
			if (__n > 0)
			{
				Element *queue_element = malloc(sizeof(*queue_element));
				queue_element->buffer_size = __n;
				queue_element->buffer_address = malloc(queue_element->buffer_size);
				memcpy(queue_element->buffer_address, temp_buf, queue_element->buffer_size);
				enqueue(recv_by_server, queue_element);
			}
			
		}
		else
		{
			Element *queue_element = malloc(sizeof(*queue_element));
			queue_element->buffer_size = __n;
			queue_element->buffer_address = malloc(queue_element->buffer_size);
			memcpy(queue_element->buffer_address, __buf, queue_element->buffer_size);

			enqueue(recv_by_server, queue_element);
		}
			
	}
	return ret;
}