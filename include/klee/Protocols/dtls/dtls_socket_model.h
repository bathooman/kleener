#ifndef DTLS_SOCKET_MODEL
#define DTLS_SOCKET_MODEL

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


ssize_t DTLS_recvfrom_model(int __fd, void *__buf, size_t __n, int __flags,
				 struct sockaddr *__addr, socklen_t *__addr_len);

int DTLS_bind_model(int sockfd, const struct sockaddr *myaddr, socklen_t addrlen);

ssize_t DTLS_sendto_model(int __fd, const void *__buf, size_t __n,
			   int __flags, const struct sockaddr *__addr,
			   socklen_t __addr_len);

#endif