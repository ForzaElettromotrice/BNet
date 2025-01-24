//
// Created by f3m on 24/01/25.
//

#include "netUtils.h"

void mySleep(const int usec)
{
    struct timespec start;
    struct timespec end;
    clock_gettime(CLOCK_MONOTONIC, &start);
    for (;;)
    {
        clock_gettime(CLOCK_MONOTONIC, &end);
        long elapsed_nsec = (end.tv_sec - start.tv_sec) * 1000000000L + (end.tv_nsec - start.tv_nsec);
        if (elapsed_nsec >= usec * 1000)
            return;
    }
}

bool isForMe(const u_char *bytes)
{
    const uint16_t radiotap_len = bytes[2] + bytes[3] * 16;
    const u_char *receiver = bytes + radiotap_len + 4;
    return strcmp((const char *) receiver, MY_ADDR) == 0;
}
bool isRTS(const u_char *bytes)
{
    const uint16_t radiotap_len = bytes[2] + bytes[3] * 16;
    const uint8_t frameType = bytes[radiotap_len];
    return frameType == RTS;
}
bool isCTS(const u_char *bytes)
{
    const uint16_t radiotap_len = bytes[2] + bytes[3] * 16;
    const uint8_t frameType = bytes[radiotap_len];
    return frameType == CTS;
}
bool isDATA(const u_char *bytes)
{
    const uint16_t radiotap_len = bytes[2] + bytes[3] * 16;
    const uint8_t frameType = bytes[radiotap_len];
    return frameType == DATA;
}
bool isACK(const u_char *bytes)
{
    const uint16_t radiotap_len = bytes[2] + bytes[3] * 16;
    const uint8_t frameType = bytes[radiotap_len];
    return frameType == ACK;
}
bool isBLOCKACK(const u_char *bytes)
{
    const uint16_t radiotap_len = bytes[2] + bytes[3] * 16;
    const uint8_t frameType = bytes[radiotap_len];
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
    const uint16_t radiotap_len = bytes[2] + bytes[3] * 16;
    return bytes[radiotap_len];
}
uint16_t getDuration(const u_char *bytes)
{
    const uint16_t radiotap_len = bytes[2] + bytes[3] * 16;
    return bytes[radiotap_len + 2] + bytes[radiotap_len + 3] * 16;
}

void getTransmitter(const u_char *bytes, u_char address[6])
{
    const uint16_t radiotap_len = bytes[2] + bytes[3] * 16;
    memcpy(address, bytes + radiotap_len + 10, 6);
}

uint32_t crc32(const unsigned char *data, const size_t length)
{
    uint32_t crc = 0xFFFFFFFF;
    for (size_t i = 0; i < length; i++)
    {
        crc ^= data[i] << 24; // Porta il byte corrente nella posizione più alta
        for (int j = 0; j < 8; j++)
        {
            // Elabora ogni bit
            if (crc & 0x80000000)
            {
                crc = (crc << 1) ^ 0x04C11DB7; // XOR con il polinomio se il bit più significativo è 1
            } else
            {
                crc <<= 1; // Shift a sinistra
            }
        }
    }
    return crc ^ 0xFFFFFFFF; // Inverti il CRC prima di restituirlo
}
