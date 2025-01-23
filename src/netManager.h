#pragma once

#include <time.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <pcap.h>

#include "logger.h"
#include "parameters.h"

#define RTS 0xb4
#define CTS 0xc4
#define ACK 0xd4
#define BLOCKACK 0x94
#define BEACON 0x80

uint16_t findLargestSIFS(pcap_t *handle);

int initPcap();
int createHandle(pcap_t **handle);
int setHandleOptions(pcap_t *handle);
int activateHandle(pcap_t *handle);
int loop(pcap_t *handle);

void cleanPcap(pcap_t *handle);
