#pragma once

#include <stdbool.h>

typedef enum PacketType PacketType_t;

int initPcap(FILE *err, FILE *debug);
void cleanPcap();

int createHandle(const char *interfaceName);
void setCallback(void (*callback)(PacketType_t, size_t, const u_char *, void *), void *userData);
int activateHandle();

void addPacket(PacketType_t type, const void *data, size_t len);

int loopPcap();
int stopPcap();

bool isQueueEmpty();
