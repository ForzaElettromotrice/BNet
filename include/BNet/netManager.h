#pragma once

#include <time.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <pcap.h>
#include <pthread.h>
#include <unistd.h>
#include <sys/wait.h>

#include "netUtils.h"

typedef enum PacketType
{
    Beacon,
    Data
} PacketType_t;

int initPcap();
void cleanPcap();

int createHandle(const char *interfaceName);
void setCallback(void (*callback)(PacketType_t, size_t, u_char *, void *), void *userData);
int activateHandle();

void addPacket(PacketType_t type, const void *data, size_t len);

int loopPcap();
int stopPcap();

bool isQueueEmpty();
