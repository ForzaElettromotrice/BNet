#pragma once

#include <time.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <pcap.h>

#include "logger.h"
#include "parameters.h"
#include "queue.h"
#include "netUtils.h"

#define RTS_LENGTH 20
#define CTS_LENGTH 14

typedef enum State
{
    CLEAR,
    WAIT_CTS,
    WAIT_DATA,
    WAIT_ACK
} State_t;


uint16_t findLargestSIFS(pcap_t *handle);

int initPcap();
int createHandle(pcap_t **handle);
int setHandleOptions(pcap_t *handle);
int activateHandle(pcap_t *handle);
int loop(pcap_t *handle);

void cleanPcap(pcap_t *handle);
