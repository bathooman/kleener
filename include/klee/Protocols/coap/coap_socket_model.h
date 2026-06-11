#ifndef COAP_SOCKET_MODEL
#define COAP_SOCKET_MODEL

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

int CoAP_bind_model(int sockfd, const struct sockaddr *addr, socklen_t addrlen);

ssize_t CoAP_sendto_model(int sockfd, const void *buf, size_t len, int flags,
                          const struct sockaddr *dest_addr, socklen_t addrlen);

ssize_t CoAP_recvfrom_model(int sockfd, void *buf, size_t len, int flags,
                            struct sockaddr *src_addr, socklen_t *addrlen);

ssize_t CoAP_sendmsg_model(int sockfd, const struct msghdr *msg, int flags);

ssize_t CoAP_recvmsg_model(int sockfd, struct msghdr *msg, int flags);

#endif
