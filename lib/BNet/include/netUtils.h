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


typedef struct MyRadiotap
{
    uint8_t version;
    uint8_t pad;
    uint16_t len;
    uint32_t fields;
    uint8_t flags;
}__attribute__((__packed__)) MyRadiotap_t;

typedef struct MyBeacon
{
    //802.11 header
    uint8_t fc;
    uint8_t flags;
    uint16_t duration;
    uint8_t raddr[6];
    uint8_t taddr[6];
    uint8_t bssid[6];
    uint16_t seq;
    //beacon fixed parameters
    uint64_t timestamp;
    uint16_t interval;
    uint16_t capabilities;
    //beacon optional parameters
    uint8_t ssid[9]; //tag + len + "AutoNet" = 1 + 1 + 7 bytes
    uint8_t vendor[257]; //tag + len + OUI + OUI type + data = 1 + 1 + 3 + 1 + 251 bytes
    //checksum
    uint32_t checksum;
}__attribute__((__packed__)) MyBeacon_t;

void mySleep(int usec);

bool isForMe(const u_char *bytes);
bool isBeacon(const u_char *bytes);
bool isRTS(const u_char *bytes);
bool isCTS(const u_char *bytes);
bool isDATA(const u_char *bytes);
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
void buildBeacon(MyBeacon_t *beacon, const u_char *data, size_t size);
