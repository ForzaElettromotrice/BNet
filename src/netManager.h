#pragma once

#include <stdlib.h>
#include <pcap.h>
#include "logger.h"

int initPcap();
int createHandle(pcap_t **handle);
int setHandleOptions(pcap_t *handle);
int activateHandle(pcap_t *handle);


void cleanPcap(pcap_t *handle);
