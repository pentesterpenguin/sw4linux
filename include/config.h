#ifndef CONFIG_H
#define CONFIG_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdint.h>
#include <stdbool.h>

#define PAYLOAD_SIZE 56
#define MAGIC        "SW4L"
#define NONCE_LEN    12
#define TAG_LEN      16
#define CT_LEN       13
#define BUF_SIZE     10000

extern const uint8_t key[32];

#endif