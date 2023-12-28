#include "klee/Protocols/quic/quic_packets.h"
#include "klee/Protocols/quic/quic_states.h"
#include "klee/Protocols/quic/quic_monitors.h"
#include "klee/Protocols/quic/quic_socket_model.h"
#include "klee/Support/Protocols/helper.h"
#include "klee/Support/Protocols/datagram.h"
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

#define DEBUG 0

static QUEUE *recv_by_server; // The queue that contains packets sent by the client
static QUEUE *recv_by_client; //The queue that contains packets sent by the server

static bool isfirst_server= true; // Is the the first time that server receives a packet
static bool isfirst_client= true; // // Is the the first time that client receives a packet

static int server_fd = 0; // File descriptor for the server
static int client_fd = 0; // File descriptor for the client



// Global MSGHDR structure to be used when Client/Server receives a packet
static struct msghdr server_message;
static struct msghdr client_message;

// Server Port
/* We need to pass the server port as an environment variable to be able to distinguish between the 
// FD for the server and the client */
static int server_port = -1;


static bool is_first_time_called = true;
static QUIC_MONITOR quic_monitor;
static quic_state state_to_check;


static void set_run_parameters(quic_state *enabling_states)
{
	SIDE side_to_check;
	int experiment;

	const char *envstate = getenv("KLEE_SYMBOLIC_EXPERIMENT");
	if (envstate == NULL)
	{
		printf("\n[Model-log] Environment Variable KLEE_SYMBOLIC_EXPERIMENT has not been set\n");
		_exit(-1);
	}
	experiment = atoi(envstate);

	const char *state_env = getenv("STATE_TO_CHECK");
	if (state_env == NULL)
	{
		printf("\n[Model-log] Environment Variable STATE_TO_CHECK has not been set\n");
		_exit(-1);
	}
	side_to_check = which_side_checked(state_env);

	quic_monitor.handle = set_quic_monitor_handle(experiment, side_to_check);
	if (quic_monitor.handle == NULL)
	{
		printf("\n[Model-log] No valid experiment is set (Normal Execution)\n");

	}
	quic_monitor.enabling_predicate = set_quic_enabling_predicate(experiment);

	*enabling_states = determine_quic_state_to_check(quic_monitor.enabling_predicate, side_to_check);

	const char *level_env = getenv("MONITOR_LEVEL");
	if (level_env == NULL)
	{
		printf("\n[Model-log] Environment Variable MONITOR_LEVEL has not been set\n");
		_exit(-1);
	}
	quic_monitor.is_packet_level = is_packet_level_monitor(level_env);

}
int QUIC_bind_model(int sockfd, const struct sockaddr *myaddr, socklen_t addrlen)
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
		set_run_parameters(&state_to_check);
		is_first_time_called = false;
	}
	return ret;
}

ssize_t QUIC_sendmsg_model(int sockfd, const struct msghdr *msg, int flags)
{
    int ret = syscall(SYS_sendmsg, sockfd, msg, flags);
	if (sockfd == server_fd)
	{
		for (int i = 0 ; i < msg->msg_iovlen; i++)
		{
			Element *queue_element = malloc(sizeof(*queue_element));
			queue_element->buffer_size = msg->msg_iov[i].iov_len;
			queue_element->buffer_address = malloc(queue_element->buffer_size);
			memcpy(queue_element->buffer_address, msg->msg_iov[i].iov_base, queue_element->buffer_size);

			enqueue(recv_by_client, queue_element);
			printf("[-] An element with the size %zu is added to the client queue\n", queue_element->buffer_size);
		}
		
	}
	else if (sockfd == client_fd)
	{
		for (int i = 0 ; i < msg->msg_iovlen; i++)
		{
			Element *queue_element = malloc(sizeof(*queue_element));
			queue_element->buffer_size = msg->msg_iov[i].iov_len;
			queue_element->buffer_address = malloc(queue_element->buffer_size);
			memcpy(queue_element->buffer_address, msg->msg_iov[i].iov_base, queue_element->buffer_size);

			enqueue(recv_by_server, queue_element);
			printf("[-] An element with the size %zu is added to the server queue\n", queue_element->buffer_size);
		}		
	}
	return ret;
}

ssize_t QUIC_recvmsg_model(int sockfd, struct msghdr *mess, int flags)
{
    // const char *envstate = getenv("KLEE_SYMBOLIC_EXPERIMENT");
	// if (envstate == NULL)
	// {
	// 	printf("\n[Model-log] Environment Variable KLEE_SYMBOLIC_EXPERIMENT has not been set\n");
	// 	_exit(-1);
	// }
    
	// uint32_t experiment = atoi(envstate);
	// // if (experiment == -1)
	// // {
	// // 	printf("\n[Model-log] The requirement is not defined\n");
	// // 	_exit(-1);
	// // }

	int ret = 0;
	if (isfirst_server && server_fd == sockfd)
	{
		ret = syscall(SYS_recvmsg, sockfd, mess, flags);
		puts("\n\nisfirst_server && server_fd == __fd\n\n");


		server_message.msg_namelen = mess->msg_namelen;
		if (mess->msg_namelen > 0)
		{
			server_message.msg_name = malloc((size_t) mess->msg_namelen);
			memcpy(server_message.msg_name, mess->msg_name, mess->msg_namelen);
		}
		server_message.msg_iovlen = mess->msg_iovlen;
		server_message.msg_flags = mess->msg_flags;
		server_message.msg_controllen = mess->msg_controllen;
		if (mess->msg_controllen > 0)
		{
			server_message.msg_control = malloc(mess->msg_controllen);
			memcpy(server_message.msg_control, mess->msg_control, mess->msg_controllen);
		}

		if (!isEmpty(recv_by_server))
		{
			/*
			* 1- We dequeue the latest datagram from the queue.
			* 2- The size of the latest datagram in the queue will be
			* the value that recvmsg returns.
			*/
			Element *item = dequeue(recv_by_server);
			mess->msg_iov->iov_len = item->buffer_size;

#if !DEBUG

				/*
			* Here we parse the datagram, apply necessary assumptions,
			* make necessary parts symbolic or check if a requirement
			* is satisfied.	In the end, we serialize the datagram back 
			* to the buffer that is returned by recvmsg. These packets 
			* are received by the server for the first time.		 	
			*/
			if (handle_quic_datagram((uint8_t *)item->buffer_address, item->buffer_size, mess->msg_iov->iov_base, 1, quic_monitor, state_to_check) == 0)
			{
				printf("[\xE2\x9C\x93] QUIC datagram is handled successfully!\n");
			}
			else
			{
				printf("Error handling the datagram! (isfirst_server)\n");
				klee_silent_exit(-1);
			}
			
		
#else
			memcpy(mess->msg_iov->iov_base, item->buffer_address, item->buffer_size);
			printf("%d bytes received.\n", mess->msg_iov->iov_len);
#endif
			ret = item->buffer_size;
			free(item->buffer_address);
			free(item);

			isfirst_server = false;
			return ret;
		}
		else
		{
			puts("\n\n recv_by_server is Empty\n\n");
			return -1;
		}
		
	}
	else if (isfirst_client && client_fd == sockfd)
	{
		ret = syscall(SYS_recvmsg, sockfd, mess, flags);
		puts("\n\nisfirst_client && client_fd == __fd\n\n");
		client_message.msg_namelen = mess->msg_namelen;
		if (mess->msg_namelen > 0)
		{
			client_message.msg_name = malloc((size_t)mess->msg_namelen);
			memcpy(client_message.msg_name, mess->msg_name, mess->msg_namelen);
		}
			
		client_message.msg_iovlen = mess->msg_iovlen;
		client_message.msg_flags = mess->msg_flags;
		client_message.msg_controllen = mess->msg_controllen;
		if (mess->msg_controllen > 0)
		{
			client_message.msg_control = malloc(mess->msg_controllen);
			memcpy(client_message.msg_control, mess->msg_control, mess->msg_controllen);
		}

		if (!isEmpty(recv_by_client))
		{
			/*
			* 1- We dequeue the latest datagram from the queue.
			* 2- The size of the latest datagram in the queue will be
			* the value that recvmsg returns.
			*/
			Element *item = dequeue(recv_by_client);
			mess->msg_iov->iov_len = item->buffer_size;

#if !DEBUG
			/*
			* Here we parse the datagram, apply necessary assumptions,
			* make necessary parts symbolic or check if a requirement
			* is satisfied.	In the end, we serialize the datagram back 
			* to the buffer that is returned by recvmsg. These packets 
			* are received by the client for the first time.		 	
			*/
			if (handle_quic_datagram((uint8_t *)item->buffer_address, item->buffer_size, mess->msg_iov->iov_base, 0, quic_monitor, state_to_check) == 0)
			{
				printf("[\xE2\x9C\x93] QUIC datagram is handled successfully!\n");
			}
			else
			{
				printf("Error handling the datagram! (isfirst_client)\n");
				klee_silent_exit(-1);
			}
#else
			memcpy(mess->msg_iov->iov_base, item->buffer_address, item->buffer_size);
			printf("%d bytes received.\n", mess->msg_iov->iov_len);
#endif
			ret = item->buffer_size;		
			free(item->buffer_address);
			free(item);
			isfirst_client = false;
			return ret;
		}
		else
		{
			puts("\n\n recv_by_client is Empty\n\n");
			return -1;
		}
		
	}
	else if (!isfirst_server && server_fd == sockfd)
	{
		
		if (!isEmpty(recv_by_server))
		{
			puts("\n\n!isfirst_server && server_fd == __fd\n\n");
			mess->msg_controllen = server_message.msg_controllen;
			if (server_message.msg_controllen > 0)
				memcpy(mess->msg_control, server_message.msg_control, server_message.msg_controllen);
			mess->msg_flags = server_message.msg_flags;
			mess->msg_iovlen = server_message.msg_iovlen;
			mess->msg_namelen = server_message.msg_namelen;
			if (server_message.msg_namelen > 0)
				memcpy(mess->msg_name, server_message.msg_name, server_message.msg_namelen);

			
			/*
			* 1- We dequeue the latest datagram from the queue.
			* 2- The size of the latest datagram in the queue will be
			* the value that recvmsg returns.
			*/
			Element *item = dequeue(recv_by_server);
			mess->msg_iov->iov_len = item->buffer_size;

#if !DEBUG
			/*
			* Here we parse the datagram, apply necessary assumptions,
			* make necessary parts symbolic or check if a requirement
			* is satisfied.	In the end, we serialize the datagram back 
			* to the buffer that is returned by recvmsg. These packets 
			* are received by the client after the first time.		 	
			*/
			if (handle_quic_datagram((uint8_t *)item->buffer_address, item->buffer_size, mess->msg_iov->iov_base, 1, quic_monitor, state_to_check) == 0)
			{
				printf("[\xE2\x9C\x93] QUIC datagram is handled successfully!\n");
			}
			else
			{
				printf("Error handling the datagram! (!isfirst_server)\n");
				klee_silent_exit(-1);
			}

#else
			memcpy(mess->msg_iov->iov_base, item->buffer_address, item->buffer_size);
			printf("%d bytes received.\n", mess->msg_iov->iov_len);
#endif
			ret = item->buffer_size;
			free(item->buffer_address);
			free(item);
			return ret;
		}
		else
		{
			puts("\n\n recv_by_server is Empty\n\n");
			return -1;
		}
	}
	else if (!isfirst_client && client_fd == sockfd)
	{		
		if (!isEmpty(recv_by_client))
		{
			puts("\n\n!isfirst_client && client_fd == __fd\n\n");
			mess->msg_controllen = client_message.msg_controllen;
			if (client_message.msg_controllen > 0)
				memcpy(mess->msg_control, client_message.msg_control, client_message.msg_controllen);
			mess->msg_flags = client_message.msg_flags;
			mess->msg_iovlen = client_message.msg_iovlen;
			mess->msg_namelen = client_message.msg_namelen;
			if (client_message.msg_namelen > 0)
				memcpy(mess->msg_name, client_message.msg_name, client_message.msg_namelen);

			/*
			* 1- We dequeue the latest datagram from the queue.
			* 2- The size of the latest datagram in the queue will be
			* the value that recvmsg returns.
			*/
			Element *item = dequeue(recv_by_client);
			mess->msg_iov->iov_len = item->buffer_size;

#if !DEBUG
			/*
			* Here we parse the datagram, apply necessary assumptions,
			* make necessary parts symbolic or check if a requirement
			* is satisfied.	In the end, we serialize the datagram back 
			* to the buffer that is returned by recvmsg. These packets 
			* are received by the client after the first time.		 	
			*/
			if (handle_quic_datagram((uint8_t *)item->buffer_address, item->buffer_size, mess->msg_iov->iov_base, 0, quic_monitor, state_to_check) == 0)
			{
				printf("[\xE2\x9C\x93] QUIC datagram is handled successfully!\n");
			}
			else
			{
				printf("Error handling the datagram! (isfirst_client)\n");
				klee_silent_exit(-1);
			}
#else

			memcpy(mess->msg_iov->iov_base, item->buffer_address, item->buffer_size);
			printf("%d bytes received.\n", mess->msg_iov->iov_len);
#endif
			ret = item->buffer_size;
			free(item->buffer_address);
			free(item);
			return ret;
		}
		else
		{
			puts("\n\n recv_by_client is Empty\n\n");
			return -1;
		}
	}

	return -1;
}

