//
// Created by f3m on 24/01/25.
//

#pragma once

#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <pcap.h>
#include <time.h>
#include <string.h>

#include "logger.h"
#include "parameters.h"

#define RTS 0xb4
#define CTS 0xc4
#define ACK 0xd4
#define DATA 0x08
#define BLOCKACK 0x94
#define BEACON 0x80

void mySleep(int usec);

bool isForMe(const u_char *bytes);
bool isRTS(const u_char *bytes);
bool isCTS(const u_char *bytes);
bool isDATA(const u_char *bytes);
bool isACK(const u_char *bytes);
bool isBLOCKACK(const u_char *bytes);
bool isChannelFree(pcap_t *handle);

uint8_t getFrameType(const u_char *bytes);
uint16_t getDuration(const u_char *bytes);

void getTransmitter(const u_char *bytes, u_char address[6]);

uint32_t crc32(const unsigned char *data, size_t length);
