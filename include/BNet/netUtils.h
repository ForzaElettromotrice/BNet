//
// Created by f3m on 24/01/25.
//

#pragma once

#include <stdbool.h>
#include <pcap.h>

#define RTS 0xb4
#define CTS 0xc4
#define ACK 0xd4
#define BLOCKACK 0x94
#define BEACON 0x80


typedef struct MyRadiotap MyRadiotap_t;

typedef struct MyBeacon MyBeacon_t;

void mySleep(long usec);

bool isForMe(const u_char *bytes, const u_char myAddr[6]);
bool isBeacon(const u_char *bytes);
bool isRTS(const u_char *bytes);
bool isCTS(const u_char *bytes);
bool isACK(const u_char *bytes);
bool isBLOCKACK(const u_char *bytes);
bool isChannelFree(pcap_t *handle);

uint8_t getFrameType(const u_char *bytes);
uint16_t getDuration(const u_char *bytes);

void getTransmitter(const u_char *bytes, u_char address[6]);
const char *getBeaconSSID(const u_char *bytes, size_t packetSize, uint8_t *tagSize);
const u_char *getBeaconData(const u_char *bytes, size_t packetSize, uint8_t *tagSize);


uint32_t crc32(const u_char *data, size_t size);

void buildRadiotap(MyRadiotap_t *radiotap);
void buildBeacon(MyBeacon_t *beacon, const u_char *data, size_t size, const u_char myAddr[6]);
