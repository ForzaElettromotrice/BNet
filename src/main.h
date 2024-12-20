#pragma once

#include <stdlib.h>
#include <unistd.h>
#include <time.h>
#include "netManager.h"


int init(pcap_t **handle);

int mainLoop(pcap_t *handle);

void clean(pcap_t *handle);
