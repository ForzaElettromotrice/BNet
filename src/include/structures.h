//
// Created by f3m on 1/15/25.
//
#pragma once

#include <stdio.h>
#include <stdint.h>
#include <queue.h>
#include <netManager.h>
#include <pcap/pcap.h>

#define DIAGNOSTIC_LENGTH 1
#define DIAGNOSTIC_TIMEOUT 1

#define SLOT_TIME 9

typedef struct Context
{
    FILE *err;
    FILE *debug;
    uint16_t sifs;
    uint16_t difs;
    u_char myAddr[6];
    pcap_t *handle;
    Queue_t *packetsQueue;
    void (*callback)(PacketType_t, size_t, const u_char *, void *);
    void *usrData;
    pthread_t thread;
    bool looping;
} Context_t;


struct MyRadiotap
{
    uint8_t version;
    uint8_t pad;
    uint16_t len;
    uint32_t fields;
    uint8_t flags;
}__attribute__((__packed__));

struct MyBeacon
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
}__attribute__((__packed__));
