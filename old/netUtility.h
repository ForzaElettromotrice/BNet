#pragma once

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <pcap.h>

#include "logger.h"

void enumerateDevices(pcap_if_t *device);

int getDevices(pcap_if_t **device);

void cleanDevices(pcap_if_t *device);
