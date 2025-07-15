#pragma once

#include <stdio.h>
#include <stdbool.h>
#include <sys/types.h>

typedef enum PacketType
{
    Beacon,
    Data
} PacketType_t;

int initPcap(FILE *err, FILE *debug);
void cleanPcap();

int createHandle(const char *interfaceName);
void setCallback(void (*callback)(PacketType_t, size_t, const u_char *, void *), void *userData);
int activateHandle();

void addPacket(PacketType_t type, const void *data, size_t len);

int loopPcap();
int stopPcap();

bool isQueueEmpty();
