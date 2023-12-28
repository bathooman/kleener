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
#include "klee/Protocols/quic/quic_socket_model.h"
#include "klee/Protocols/dtls/dtls_socket_model.h"


// The model for the socket function
// Todo: Remove the real syscall
int socket(int family, int type, int protocol)
{
	long sockfd = syscall(SYS_socket, family, type, protocol);
	if (sockfd < 0)
	{
		printf("\n[Model-log] socket() failed\n");
	}

	int enable = 1;
	if (syscall(SYS_setsockopt, sockfd, SOL_SOCKET, SO_REUSEADDR, &enable, sizeof(int)) < 0)
		printf("\n[Model-log]setsockopt(SO_REUSEADDR) failed\n");

	return sockfd;
}

// The model for the setsockopt function
// Todo: Remove the real syscall
int setsockopt(int __fd, int __level, int __optname,
			   const void *__optval, socklen_t __optlen)
{
	int ret = syscall(SYS_setsockopt, __fd, __level, __optname, __optval, __optlen);
	if (ret < 0)
	{
		printf("\n[Model-setsockopt] setsockopt() has been failed!\n");
	}
	return ret;
}


// The model for the bind function
// Todo: Remove the real syscall
int bind(int sockfd, const struct sockaddr *myaddr, socklen_t addrlen)
{
	const char *envstate = getenv("PROTOCOL");
	if (envstate == NULL)
	{
		printf("\n[Model-log] Environment Variable PROTOCOL has not been set\n");
		_exit(-1);
	}
	else if (strcmp(envstate, "DTLS") == 0)
	{
		return DTLS_bind_model(sockfd, myaddr, addrlen);
	}
	else if (strcmp(envstate, "QUIC") == 0)
	{
		return QUIC_bind_model(sockfd, myaddr, addrlen);
	}
	else
	{
		printf("\n[Model-log] The protocol is not supported\n");
		_exit(-1);
	}
	return 0;
}

ssize_t recvfrom(int __fd, void *__buf, size_t __n, int __flags,
				 struct sockaddr *__addr, socklen_t *__addr_len)
{
	const char *envstate = getenv("PROTOCOL");
	if (envstate == NULL)
	{
		printf("\n[Model-log] Environment Variable PROTOCOL has not been set\n");
		_exit(-1);
	}
	else if (strcmp(envstate, "DTLS") == 0)
	{
		return DTLS_recvfrom_model(__fd, __buf, __n, __flags, __addr, __addr_len);
	}
	else
	{
		printf("\n[Model-log] The protocol is not supported\n");
		_exit(-1);
	}
	return 0;
}

ssize_t sendto(int __fd, const void *__buf, size_t __n,
			   int __flags, const struct sockaddr *__addr,
			   socklen_t __addr_len)
{
	const char *envstate = getenv("PROTOCOL");
	if (envstate == NULL)
	{
		printf("\n[Model-log] Environment Variable PROTOCOL has not been set\n");
		_exit(-1);
	}
	else if (strcmp(envstate, "DTLS") == 0)
	{
		return DTLS_sendto_model(__fd, __buf, __n, __flags, __addr, __addr_len);
	}
	else
	{
		printf("\n[Model-log] The protocol is not supported\n");
		_exit(-1);
	}
	return 0;
}


ssize_t recvmsg(int sockfd, struct msghdr *mess, int flags)
{
	const char *envstate = getenv("PROTOCOL");
	if (envstate == NULL)
	{
		printf("\n[Model-log] Environment Variable PROTOCOL has not been set\n");
		_exit(-1);
	}
	else if (strcmp(envstate, "QUIC") == 0)
	{
		return QUIC_recvmsg_model(sockfd, mess, flags);
	}
	else
	{
		printf("\n[Model-log] The protocol is not supported\n");
		_exit(-1);
	}
	return 0;

}

ssize_t sendmsg(int sockfd, const struct msghdr *msg, int flags)
{	
	const char *envstate = getenv("PROTOCOL");
	if (envstate == NULL)
	{
		printf("\n[Model-log] Environment Variable PROTOCOL has not been set\n");
		_exit(-1);
	}
	else if (strcmp(envstate, "QUIC") == 0)
	{
		return QUIC_sendmsg_model(sockfd, msg, flags);
	}
	else
	{
		printf("\n[Model-log] The protocol is not supported\n");
		_exit(-1);
	}
	return 0;
}

int connect(int sockfd, const struct sockaddr *addr,
			socklen_t addrlen)
{
	int ret = syscall(SYS_connect, sockfd, addr, addrlen);
	if (ret < 0)
	{
		printf("\n[Model-sockfd] connect() failed\n");
	}
	return ret;
}

int getsockopt(int fd, int level, int optname, __ptr_t optval,
		   socklen_t * optlen)
{
	int ret = syscall(SYS_getsockopt, fd, level, optname, optval, optlen);
	if (ret < 0)
	{
		printf("\n[Model-getsockopt] getsockopt() failed\n");
	}
	return ret;
}

int getsockname(int sockfd, struct sockaddr *addr, socklen_t * paddrlen)
{
	int ret = syscall(SYS_getsockname, sockfd, addr, paddrlen);
	if (ret < 0)
	{
		printf("\n[Model-getsockname] getsockname() failed\n");
	}
	return ret;
}

int shutdown (int __fd, int __how)
{
	int ret = syscall(SYS_shutdown, __fd, __how);
	if (ret < 0)
	{
		printf("\n[Model-log] shutdown() failed\n");
	}
	exit(0);
	return ret;
}