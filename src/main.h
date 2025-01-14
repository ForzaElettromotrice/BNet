#pragma once

#include <stdlib.h>
#include "netManager.h"


int init(pcap_t **handle);

int mainLoop(pcap_t *handle);

void clean(pcap_t *handle);
