#pragma once

#include <time.h>
#include <stdlib.h>
#include <stdbool.h>
#include <pcap.h>

#include "logger.h"

#define RTS 0xb4
#define CTS 0xc4
#define ACK 0xd4
#define BLOCKACK 0x94
#define BEACON 0x80

typedef struct Header80211 {
    uint8_t type;
    uint8_t flags;
    uint16_t durationId;
    char addr1[6];
    char addr2[6];
    char addr3[6];
}Header80211_t;

int findSIFS(pcap_t *handle);


int initPcap();
int createHandle(pcap_t **handle);
int setHandleOptions(pcap_t *handle);
int activateHandle(pcap_t *handle);
int loop(pcap_t *handle);

void cleanPcap(pcap_t *handle);
