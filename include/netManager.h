#pragma once

#include <time.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <pcap.h>
#include <pthread.h>

#include "logger.h"
#include "parameters.h"
#include "queue.h"
#include "netUtils.h"

typedef enum PacketType
{
    Beacon,
    Data
} PacketType_t;

int initPcap();
void cleanPcap(pcap_t *handle);

int createHandle(pcap_t **handle);
int setHandleOptions(pcap_t *handle);
void setCallback(void (*callback)(PacketType_t, size_t, u_char *));
int activateHandle(pcap_t *handle);

void addPacket(PacketType_t type, const void *data, size_t len);

int loopPcap(pcap_t *handle);
int stopPcap();
