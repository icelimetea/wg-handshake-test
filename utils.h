#ifndef _UTILS_H
#define _UTILS_H

#include <sys/socket.h>

int get_env_option(const char* desc, const char* name, const char** value);

int resolve_udp_address(const char* host, const char* port, socklen_t* addr_len, struct sockaddr_storage* addr_buf);

#endif
