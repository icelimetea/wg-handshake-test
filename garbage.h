#ifndef GARBAGE_H
#define GARBAGE_H

#include <stdint.h>
#include <sys/uio.h>

const uint8_t DNS1[] = {
#embed "garbage/dns1.bin"
};

const uint8_t DNS2[] = {
#embed "garbage/dns2.bin"
};

const uint8_t DNS3[] = {
#embed "garbage/dns3.bin"
};

const uint8_t DNS4[] = {
#embed "garbage/dns4.bin"
};

const uint8_t DNS5[] = {
#embed "garbage/dns5.bin"
};

const uint8_t DNS6[] = {
#embed "garbage/dns6.bin"
};

const uint8_t DNS7[] = {
#embed "garbage/dns7.bin"
};

const uint8_t DNS8[] = {
#embed "garbage/dns8.bin"
};

const uint8_t DNS9[] = {
#embed "garbage/dns9.bin"
};

const uint8_t DNS10[] = {
#embed "garbage/dns10.bin"
};

const uint8_t DNS11[] = {
#embed "garbage/dns11.bin"
};

const uint8_t DNS12[] = {
#embed "garbage/dns12.bin"
};

const uint8_t DNS13[] = {
#embed "garbage/dns13.bin"
};

const uint8_t DNS14[] = {
#embed "garbage/dns14.bin"
};

const uint8_t DNS15[] = {
#embed "garbage/dns15.bin"
};

const struct iovec GARBAGE_PACKETS[] = {
	{ .iov_base = (void*) DNS1, .iov_len = sizeof(DNS1) },
	{ .iov_base = (void*) DNS2, .iov_len = sizeof(DNS2) },
	{ .iov_base = (void*) DNS3, .iov_len = sizeof(DNS3) },
	{ .iov_base = (void*) DNS4, .iov_len = sizeof(DNS4) },
	{ .iov_base = (void*) DNS5, .iov_len = sizeof(DNS5) },
	{ .iov_base = (void*) DNS6, .iov_len = sizeof(DNS6) },
	{ .iov_base = (void*) DNS7, .iov_len = sizeof(DNS7) },
	{ .iov_base = (void*) DNS8, .iov_len = sizeof(DNS8) },
	{ .iov_base = (void*) DNS9, .iov_len = sizeof(DNS9) },
	{ .iov_base = (void*) DNS10, .iov_len = sizeof(DNS10) },
	{ .iov_base = (void*) DNS11, .iov_len = sizeof(DNS11) },
	{ .iov_base = (void*) DNS12, .iov_len = sizeof(DNS12) },
	{ .iov_base = (void*) DNS13, .iov_len = sizeof(DNS13) },
	{ .iov_base = (void*) DNS14, .iov_len = sizeof(DNS14) },
	{ .iov_base = (void*) DNS15, .iov_len = sizeof(DNS15) }
};

const size_t GARBAGE_PACKETS_COUNT = sizeof(GARBAGE_PACKETS);

#endif
