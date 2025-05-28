//
// Created by f3m on 28/05/25.
//

#include <stdint.h>
#include <time.h>
#include <string.h>
#include <netUtils.h>
#include <structures.h>

void mySleep(const long usec)
{
    struct timespec start;
    struct timespec end;
    clock_gettime(CLOCK_MONOTONIC, &start);
    for (;;)
    {
        clock_gettime(CLOCK_MONOTONIC, &end);
        const long elapsed_nsec = (end.tv_sec - start.tv_sec) * 1000000000L + (end.tv_nsec - start.tv_nsec);
        if (elapsed_nsec >= usec * 1000)
            return;
    }
}

bool isForMe(const u_char *bytes, const u_char myAddr[6])
{
    const uint16_t radiotapLen = bytes[2] + bytes[3] * 16;
    const u_char *receiver = bytes + radiotapLen + 4;

    for (int i = 0; i < 6; ++i)
    {
        if (receiver[i] != myAddr[i] && receiver[i] != 0xff)
            return false;
    }

    return true;
}
bool isBeacon(const u_char *bytes)
{
    const uint16_t radiotapLen = bytes[2] + bytes[3] * 16;
    const uint8_t frameType = bytes[radiotapLen];
    return frameType == BEACON;
}
bool isRTS(const u_char *bytes)
{
    const uint16_t radiotapLen = bytes[2] + bytes[3] * 16;
    const uint8_t frameType = bytes[radiotapLen];
    return frameType == RTS;
}
bool isCTS(const u_char *bytes)
{
    const uint16_t radiotapLen = bytes[2] + bytes[3] * 16;
    const uint8_t frameType = bytes[radiotapLen];
    return frameType == CTS;
}
bool isACK(const u_char *bytes)
{
    const uint16_t radiotapLen = bytes[2] + bytes[3] * 16;
    const uint8_t frameType = bytes[radiotapLen];
    return frameType == ACK;
}
bool isBLOCKACK(const u_char *bytes)
{
    const uint16_t radiotapLen = bytes[2] + bytes[3] * 16;
    const uint8_t frameType = bytes[radiotapLen];
    return frameType == BLOCKACK;
}
bool isChannelFree(pcap_t *handle)
{
    struct pcap_pkthdr *header;
    const u_char *packet;
    const int result = pcap_next_ex(handle, &header, &packet);
    return result == 0;
}

uint8_t getFrameType(const u_char *bytes)
{
    const uint16_t radiotapLen = bytes[2] + bytes[3] * 16;
    return bytes[radiotapLen];
}
uint16_t getDuration(const u_char *bytes)
{
    const uint16_t radiotapLen = bytes[2] + bytes[3] * 16;
    return bytes[radiotapLen + 2] + bytes[radiotapLen + 3] * 16;
}

void getTransmitter(const u_char *bytes, u_char address[6])
{
    const uint16_t radiotapLen = bytes[2] + bytes[3] * 16;
    memcpy(address, bytes + radiotapLen + 10, 6);
}
const char *getBeaconSSID(const u_char *bytes, const size_t packetSize, uint8_t *tagSize)
{
    const uint16_t radiotapLen = bytes[2] + bytes[3] * 16;

    size_t pointer = radiotapLen + 36;

    while (pointer < packetSize - 4)
    {
        const int8_t tagLen = (int8_t) bytes[pointer + 1];
        if (bytes[pointer] != 0x00)
        {
            pointer += tagLen + 2;
            continue;
        }

        *tagSize = tagLen;
        return (char *) &bytes[pointer + 2];
    }

    *tagSize = 0;
    return NULL;
}
const u_char *getBeaconData(const u_char *bytes, const size_t packetSize, uint8_t *tagSize)
{
    //TODO: unire alla funzione sopra
    const uint16_t radiotapLen = bytes[2] + bytes[3] * 16;

    size_t pointer = radiotapLen + 36;

    while (pointer < packetSize - 4)
    {
        const uint8_t tagLen = (int8_t) bytes[pointer + 1];
        if (bytes[pointer] != 0xdd)
        {
            pointer += tagLen + 2;
            continue;
        }

        *tagSize = tagLen;
        return &bytes[pointer + 2];
    }

    *tagSize = 0;
    return NULL;
}


void buildRadiotap(MyRadiotap_t *radiotap)
{
    radiotap->version = 0x00;
    radiotap->pad = 0x00;
    radiotap->len = 0x0009;
    radiotap->fields = 0x00000002;
    radiotap->flags = 0x10;
}
void buildBeacon(MyBeacon_t *beacon, const u_char *data, size_t size, const u_char myAddr[6])
{
    //TODO: se il dato è piu piccolo, scrivere 0 in tutta la memoria restante
    //TODO: se il dato è piu piccolo volendo si potrebbe fare il pacchetto più piccolo
    if (size > 251)
        size = 251;

    beacon->fc = BEACON;
    beacon->flags = 0x00; // da rivedere
    beacon->duration = 0x0000;
    memset(beacon->raddr, 0xff, 6);
    memcpy(beacon->taddr, myAddr, 6);
    memcpy(beacon->bssid, myAddr, 6);
    beacon->seq = 0x0000; // da rivedere
    beacon->timestamp = 0x0011223344556677; // da rivedere
    beacon->interval = 0x0064;
    beacon->capabilities = 0x0002;
    beacon->ssid[0] = 0x00;
    beacon->ssid[1] = 0x07;
    memcpy(&beacon->ssid[2], "AutoNet", 7);
    beacon->vendor[0] = 0xdd;
    beacon->vendor[1] = 0xff;
    beacon->vendor[2] = 0x00; //OUI da rivedere
    beacon->vendor[3] = 0x11;
    beacon->vendor[4] = 0x22;
    beacon->vendor[5] = 0x01; //OUI type da rivedere
    memcpy(&beacon->vendor[6], data, size);
    beacon->checksum = 0; //in teoria viene calcolata in automatico dalla scheda
}
