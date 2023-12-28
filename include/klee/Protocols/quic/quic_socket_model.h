#ifndef QUIC_SOCKET_MODEL
#define QUIC_SOCKET_MODEL

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>

int QUIC_bind_model(int sockfd, const struct sockaddr *myaddr, socklen_t addrlen);
ssize_t QUIC_sendmsg_model(int sockfd, const struct msghdr *msg, int flags);
ssize_t QUIC_recvmsg_model(int sockfd, struct msghdr *mess, int flags);

#endif