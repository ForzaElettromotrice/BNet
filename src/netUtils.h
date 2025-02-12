//
// Created by f3m on 24/01/25.
//

#pragma once

#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <pcap.h>
#include <time.h>
#include <string.h>

#include "logger.h"
#include "parameters.h"

#define RTS 0xb4
#define CTS 0xc4
#define ACK 0xd4
#define DATA 0x08
#define BLOCKACK 0x94
#define BEACON 0x80


typedef struct MyRadiotap
{
    uint8_t version;
    uint8_t pad;
    uint16_t len; // little endian
    uint32_t fields; // little endian
    uint8_t flags;
    uint8_t rate;
    uint16_t frequency; //little endian
    uint16_t channelFlags; //little endian
    uint8_t power;
    uint8_t antenna;
    uint16_t txFlags; //little endian
    uint8_t MCSKnown;
    uint8_t MCSFlags;
    uint8_t MCS;
}__attribute__((__packed__)) MyRadiotap_t;

void mySleep(int usec);

bool isForMe(const u_char *bytes);
bool isRTS(const u_char *bytes);
bool isCTS(const u_char *bytes);
bool isDATA(const u_char *bytes);
bool isACK(const u_char *bytes);
bool isBLOCKACK(const u_char *bytes);
bool isChannelFree(pcap_t *handle);

uint8_t getFrameType(const u_char *bytes);
uint16_t getDuration(const u_char *bytes);

void getTransmitter(const u_char *bytes, u_char address[6]);

uint32_t crc32(const u_char *data, size_t size);

void buildRadiotap(MyRadiotap_t *radiotap);

/**
 * Version -> 0
 * Padding -> 0
 * Len -> da calcolare
 * fields: (4 byte) (Da 0 -> 31)
 * 0 	TSFT -> 0
 * 1 	Flags -> 1 (1 byte) (Da 0 -> 7)
 *      - 0x01 	sent/received during CFP -> 0
 *      - 0x02 	sent/received with short preamble -> 0
 *      - 0x04 	sent/received with WEP encryption -> 0
 *      - 0x08 	sent/received with fragmentation -> 0
 *      - 0x10 	frame includes FCS -> 1
 *      - 0x20 	frame has padding between 802.11 header and payload (to 32-bit boundary) -> 0
 *      - 0x40 	frame failed FCS check -> 0
 *      - 0x80 	frame used short guard interval (HT) -> 0
 * 2 	Rate -> 1 (1 byte) (misurato in 500 Kbps) -> 130 (65 Mbps)
 * 3 	Channel -> 1
 *      - Frequenza (2 byte) (MHz) (Little Endian) -> da decidere
 *      - Flags (2 byte) (da 0 -> 15)
 *      - 0x0001 	S1G 700MHz spectrum channel -> 0
 *      - 0x0002 	S1G 800MHz spectrum channel -> 0
 *      - 0x0004 	S1G 900MHz spectrum channel -> 0
 *      - 0x0010 	Turbo Channel -> 0
 *      - 0x0020 	CCK channel -> 0
 *      - 0x0040 	OFDM channel -> 1
 *      - 0x0080 	2 GHz spectrum channel -> 1
 *      - 0x0100 	5 GHz spectrum channel -> 0
 *      - 0x0200 	Only passive scan allowed -> 0
 *      - 0x0400 	Dynamic CCK-OFDM channel -> 0
 *      - 0x0800 	GFSK channel (FHSS PHY) -> 0
 * 4 	FHSS -> 0
 * 5 	Antenna signal -> 0
 * 6 	Antenna noise --> 0
 * 7 	Lock quality --> 0
 * 8 	TX attenuation --> 0
 * 9 	dB TX attenuation --> 0
 * 10 	dBm TX power --> 1 (1 byte) (1 byte allineamento) --> fino a 20 dBm
 * 11 	Antenna --> 1 (1 byte) --> Dovrebbe essere 1
 * 12 	dB antenna signal --> 0
 * 13 	dB antenna noise --> 0
 * 14 	RX flags --> 0
 * 15 	TX flags --> 1
 *          - 0x0001 	Transmission failed due to excessive retries --> 0
 *          - 0x0002 	Transmission used CTS-to-self protection --> 0
 *          - 0x0004 	Transmission used RTS/CTS handshake --> 0
 *          - 0x0008 	Transmission shall not expect an ACK frame and not retry when no ACK is received --> 1
 *          - 0x0010 	Transmission includes a pre-configured sequence number that should not be changed by the driver’s TX handlers --> 1
 *          - 0x0020 	Transmission should not be reordered relative to other frames that have this flag set --> 1
 * 16   Non in lista -->0
 * 17   Non in lista -->0
 * 18   Non in lista -->0
 * 19 	MCS --> 1 (3 byte) (1 byte allineamento)
 *      - Know
 *      - 0x01 	bandwidth --> 1
 *      - 0x02 	MCS index known (in mcs part of the field) --> 1
 *      - 0x04 	guard interval --> 1
 *      - 0x08 	HT format --> 1
 *      - 0x10 	FEC type --> 1
 *      - 0x20 	STBC known --> 1
 *      - 0x40 	Ness known (Number of extension spatial streams) --> 1
 *      - 0x80 	Ness data - bit 1 (MSB) of Number of extension spatial streams --> 0
 *      - Flags
 *      - 0x03 	bandwidth - 0: 20, 1: 40, 2: 20L, 3: 20U --> 1
 *      - 0x04 	guard interval - 0: long GI, 1: short GI --> 0
 *      - 0x08 	HT format - 0: mixed, 1: greenfield --> 0
 *      - 0x10 	FEC type - 0: BCC, 1: LDPC --> 0
 *      - 0x60 	Number of STBC streams --> 01
 *      - 0x80 	Ness - bit 0 (LSB) of Number of extension spatial streams --> 0
 *      - MCS index --> 7
 * 20 	A-MPDU status --> 0
 * 21 	VHT --> 0
 * 22 	timestamp --> 0
 * 23 	HE --> 0
 * 24 	HE-MU --> 0
 * 25 	HE-MU-other-user --> 0
 * 26 	0-length-PSDU --> 0
 * 27 	L-SIG --> 0
 * 28 	TLV fields in radiotap --> 0
 * 29 	Radiotap Namespace --> 1
 * 30 	Vendor Namespace --> 0
 * 31   Altra tabella --> 0
 */
