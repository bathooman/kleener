#include "klee/Protocols/coap/coap_socket_model.h"
#include "klee/Protocols/coap/coap_packets.h"
#include "klee/Protocols/coap/coap_monitors.h"
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
#include <assert.h>

static QUEUE *recv_by_server; // The queue that contains packets sent by the client
static QUEUE *recv_by_client; // The queue that contains packets sent by the server

static bool isfirst_server = true; // Is the first time that server receives a packet
static bool isfirst_client = true; // Is the first time that client receives a packet

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


/* KLEE_SYMBOLIC_EXPERIMENT selects which monitor the dispatcher runs. */

static int cached_experiment = -1;

static int get_experiment(void)
{
	if (cached_experiment == -1)
	{
		const char *env = getenv("KLEE_SYMBOLIC_EXPERIMENT");
		cached_experiment = (env != NULL) ? atoi(env) : coap_normal_execution;
	}
	return cached_experiment;
}

static bool monitor_initialized = false;
static COAP_MONITOR cached_dispatched_monitor;

/* Bounded-exchange response accounting. The server's only outbound traffic is
 * its response to the (injected) request, so counting its sends tells us
 * whether it answered or silently dropped — see coap_exchange_finalize. */
static int server_response_count = 0;

static void ensure_monitor_initialized(void)
{
	if (!monitor_initialized)
	{
		const char *side_env = getenv("STATE_TO_CHECK");
		SIDE side = (side_env != NULL) ? which_side_checked(side_env) : SERVER;
		cached_dispatched_monitor.handle =
			set_coap_monitor_handle(get_experiment(), side);
		monitor_initialized = true;
	}
}

/* Does the active requirement mandate that the SUT produce a response? For
 * these, a silent drop is itself a non-conformance (the inbound request is
 * either valid and must be answered, or malformed in a way the RFC says MUST
 * elicit a specific error response). coap_exchange_finalize catches that drop;
 * requirements where dropping is the correct reaction return false here. */
static bool coap_requirement_expects_response(int exp)
{
	switch (exp)
	{
	case coap_unrecognized_opts_requirement: /* RFC 7252 §5.4.1: MUST return 4.02 */
	case coap_mid_match_requirement:         /* valid request MUST be answered (MID echo) */
	case coap_token_match_requirement:       /* valid request MUST be answered (token echo) */
		return true;
	default:
		return false;
	}
}

/* Called by the harness once its bounded exchange loop ends. If the requirement
 * demanded a response and the server produced none (a silent drop), fire here —
 * this turns a drop from invisible silence into a caught violation, without the
 * harness having to spin to max-time to "observe" the absence of a response. */
void coap_exchange_finalize(void)
{
	if (coap_requirement_expects_response(get_experiment()) &&
	    server_response_count == 0)
	{
		assert(0 && "SUT produced no response to a message that requires one");
	}
}


int CoAP_bind_model(int sockfd, const struct sockaddr *myaddr, socklen_t addrlen)
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
	uint16_t port = ntohs(address->sin_port);


	if (port == server_port)
	{
		server_fd = sockfd;
	}
	else
	{
		client_fd = sockfd;
	}

	return ret;
}


ssize_t CoAP_recvfrom_model(int __fd, void *__buf, size_t __n, int __flags,
				 struct sockaddr *__addr, socklen_t *__addr_len)
{
	/* Caller's receive-buffer capacity, captured before __n is reused as the
	 * per-message length. Used as the output bound so a size-growing monitor
	 * can serialize without overflow. */
	size_t buf_cap = __n;

	if (isfirst_server && server_fd == __fd)
	{
		Element *item;
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
		if (__addr != NULL && __addr_len != NULL && *__addr_len > 0)
		{
			server_addr_len = *__addr_len;
			server_addr = malloc(*__addr_len);
			memcpy(server_addr, __addr, *__addr_len);
		}

		ensure_monitor_initialized();
		{
			ssize_t produced = handle_coap_message(item->buffer_address, item->buffer_size,
			                                       __buf, buf_cap,
			                                       true, cached_dispatched_monitor);
			if (produced < 0)
			{
				/* parse/serialize failed — pass the original datagram through */
				memcpy(__buf, item->buffer_address, item->buffer_size);
			}
			else
			{
				/* monitor may have resized the message — return its true length */
				__n = (size_t)produced;
			}
		}

		isfirst_server = false;
		free(item->buffer_address);
		free(item);
	}
	else if (isfirst_client && server_fd != __fd)
	{
		Element *item;
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
		if (__addr != NULL && __addr_len != NULL && *__addr_len > 0)
		{
			client_addr_len = *__addr_len;
			client_addr = malloc(*__addr_len);
			memcpy(client_addr, __addr, *__addr_len);
		}

		ensure_monitor_initialized();
		{
			ssize_t produced = handle_coap_message(item->buffer_address, item->buffer_size,
			                                       __buf, buf_cap,
			                                       false, cached_dispatched_monitor);
			if (produced < 0)
			{
				/* parse/serialize failed — pass the original datagram through */
				memcpy(__buf, item->buffer_address, item->buffer_size);
			}
			else
			{
				/* monitor may have resized the message — return its true length */
				__n = (size_t)produced;
			}
		}

		isfirst_client = false;
		free(item->buffer_address);
		free(item);

	}
	else if (!isfirst_server && server_fd == __fd)
	{
		Element *item;
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
		if (__addr != NULL && __addr_len != NULL && server_addr != NULL)
		{
			memcpy(__addr, server_addr, server_addr_len);
			*__addr_len = server_addr_len;
		}

		ensure_monitor_initialized();
		{
			ssize_t produced = handle_coap_message(item->buffer_address, item->buffer_size,
			                                       __buf, buf_cap,
			                                       true, cached_dispatched_monitor);
			if (produced < 0)
			{
				/* parse/serialize failed — pass the original datagram through */
				memcpy(__buf, item->buffer_address, item->buffer_size);
			}
			else
			{
				/* monitor may have resized the message — return its true length */
				__n = (size_t)produced;
			}
		}

		free(item->buffer_address);
		free(item);
	}
	else if (!isfirst_client && server_fd != __fd)
	{
		Element *item;

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
		if (__addr != NULL && __addr_len != NULL && client_addr != NULL)
		{
			memcpy(__addr, client_addr, client_addr_len);
			*__addr_len = client_addr_len;
		}

		ensure_monitor_initialized();
		{
			ssize_t produced = handle_coap_message(item->buffer_address, item->buffer_size,
			                                       __buf, buf_cap,
			                                       false, cached_dispatched_monitor);
			if (produced < 0)
			{
				/* parse/serialize failed — pass the original datagram through */
				memcpy(__buf, item->buffer_address, item->buffer_size);
			}
			else
			{
				/* monitor may have resized the message — return its true length */
				__n = (size_t)produced;
			}
		}

		free(item->buffer_address);
		free(item);
	}
	return __n;
}

ssize_t CoAP_sendto_model(int __fd, const void *__buf, size_t __n,
			   int __flags, const struct sockaddr *__addr,
			   socklen_t __addr_len)
{
	int ret = syscall(SYS_sendto, __fd, __buf, __n, __flags, __addr, __addr_len);
	if (ret < 0)
	{
		printf("\n[Model-log] sendto() failed\n");
	}

	if (__fd == server_fd)
	{
		server_response_count++;   /* the server answered (vs. silently dropping) */

		Element *queue_element = malloc(sizeof(*queue_element));
		queue_element->buffer_size = __n;
		queue_element->buffer_address = malloc(queue_element->buffer_size);
		memcpy(queue_element->buffer_address, __buf, queue_element->buffer_size);

		enqueue(recv_by_client, queue_element);
	}
	else
	{
		Element *queue_element = malloc(sizeof(*queue_element));
		queue_element->buffer_size = __n;
		queue_element->buffer_address = malloc(queue_element->buffer_size);
		memcpy(queue_element->buffer_address, __buf, queue_element->buffer_size);

		enqueue(recv_by_server, queue_element);
	}
	return ret;
}

/* ---- sendmsg / recvmsg adapters: flatten msghdr and delegate ---- */

ssize_t CoAP_sendmsg_model(int sockfd, const struct msghdr *msg, int flags)
{
	size_t total = 0;
	int i;
	uint8_t *buf;
	size_t off;
	ssize_t ret;

	for (i = 0; i < msg->msg_iovlen; i++)
		total += msg->msg_iov[i].iov_len;

	buf = malloc(total);
	off = 0;
	for (i = 0; i < msg->msg_iovlen; i++)
	{
		memcpy(buf + off, msg->msg_iov[i].iov_base, msg->msg_iov[i].iov_len);
		off += msg->msg_iov[i].iov_len;
	}

	ret = CoAP_sendto_model(sockfd, buf, total, flags,
	                        (const struct sockaddr *)msg->msg_name,
	                        msg->msg_namelen);
	free(buf);
	return ret;
}

ssize_t CoAP_recvmsg_model(int sockfd, struct msghdr *msg, int flags)
{
	socklen_t namelen = msg->msg_namelen;
	ssize_t n;

	/* libcoap's recvmsg call uses a single iov for the datagram. */
	n = CoAP_recvfrom_model(sockfd,
	                        msg->msg_iov[0].iov_base,
	                        msg->msg_iov[0].iov_len,
	                        flags,
	                        (struct sockaddr *)msg->msg_name,
	                        &namelen);
	msg->msg_namelen = namelen;
	msg->msg_controllen = 0;
	msg->msg_flags = 0;
	return n;
}
