#include "netManager.h"

uint16_t sifs = 0;
uint16_t difs = 0;

Queue_t *packetsQueue;

int sendPacket(pcap_t *handle)
{
    size_t size;
    void *packet;
    if (popQueue(packetsQueue, &packet, &size))
    {
        E_Print("Error while sending packet!\n");
        return EXIT_FAILURE;
    }

    const int result = pcap_inject(handle, packet, size);
    if (result == PCAP_ERROR)
    {
        pushFirstQueue(packet, size, packetsQueue);
        E_Print("inject: %s\n", pcap_geterr(handle));
        return EXIT_FAILURE;
    }

    free(packet);
    return EXIT_SUCCESS;
}
void makeCTS(const u_char *p, u_char packet[CTS_LENGTH])
{
    const uint8_t frameType = CTS;
    const uint8_t flags = 0x0; //per ora non le usiamo
    const uint16_t duration = getDuration(p) - sifs; //TODO: togliere il tempo di trasmissione
    u_char address[6];
    getTransmitter(p, address);
    memcpy(packet, &frameType, sizeof(uint8_t));
    memcpy(packet, &flags, sizeof(uint8_t));
    memcpy(packet, &duration, sizeof(uint16_t));
    memcpy(packet, address, 6);

    const uint32_t checksum = crc32(packet, CTS_LENGTH - 4);
    memcpy(packet + CTS_LENGTH - 4, &checksum, sizeof(uint32_t));
}


int sendCTS(pcap_t *handle, const u_char *p)
{
    u_char packet[CTS_LENGTH];
    makeCTS(p, packet);

    const int result = pcap_inject(handle, packet, CTS_LENGTH);
    if (result == PCAP_ERROR)
    {
        E_Print("inject cts: %s\n", pcap_geterr(handle));
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}

uint16_t findSIFS(pcap_t *handle)
{
    struct pcap_pkthdr *header;
    const u_char *packet;

    char errbuf[PCAP_ERRBUF_SIZE];
    if (pcap_setnonblock(handle, 1, errbuf))
    {
        E_Print("Setnonblock: %s\n", errbuf);
        return EXIT_FAILURE;
    }

    bool rts = false;
    struct timeval rtsTimestamp = {};
    struct timeval ctsTimestamp = {};

    struct timespec start = {};
    struct timespec end = {};

    clock_gettime(CLOCK_MONOTONIC, &start);
    for (int i = 0; i < 20000; ++i)
    {
        const int result = pcap_next_ex(handle, &header, &packet);
        if (result == 0)
        {
            clock_gettime(CLOCK_MONOTONIC, &end);
            if (end.tv_sec - start.tv_sec >= DIAGNOSTIC_TIMEOUT)
                return -1;
            continue;
        }
        if (result != 1)
            return -1;
        if (!rts)
        {
            rts = isRTS(packet);
            if (rts)
                memcpy(&rtsTimestamp, &header->ts, sizeof(struct timeval));
            continue;
        }
        if (isCTS(packet))
        {
            memcpy(&ctsTimestamp, &header->ts, sizeof(struct timeval));
            break;
        }
        rts = false;
    }

    const long s = rtsTimestamp.tv_sec * 1000000L + rtsTimestamp.tv_usec;
    const long e = ctsTimestamp.tv_sec * 1000000L + ctsTimestamp.tv_usec;

    return e - s;
}
uint16_t findLargestSIFS(pcap_t *handle)
{
    int mean = 0;
    for (int i = 0; i < DIAGNOSTIC_LENGTH; ++i)
    {
        const int val = findSIFS(handle);
        if (val <= 0 || val >= 500)
        {
            i--;
            continue;
        }
        mean += val;
    }
    mean /= DIAGNOSTIC_LENGTH;

    return mean;
}

int initPcap()
{
    char errbuf[PCAP_ERRBUF_SIZE];
    if (pcap_init(PCAP_CHAR_ENC_LOCAL, errbuf))
    {
        E_Print("Pcap init failed: %s\n", errbuf);
        return EXIT_FAILURE;
    }

    if (initQueue(&packetsQueue))
    {
        E_Print("Error while initiating the packets queue\n");
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}
int createHandle(pcap_t **handle)
{
    char errbuf[PCAP_ERRBUF_SIZE];

    *handle = pcap_create("wlan1", errbuf);
    if (!*handle)
    {
        E_Print("pcap_create: %s\n", errbuf);
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}
int setHandleOptions(pcap_t *handle)
{
    // TODO: delay (packet buffer timeout) fra una lettura di un pacchetto e l'altra, non so se metterlo
    // TODO: in caso si può mettere la immediate mode
    const int result = pcap_set_immediate_mode(handle, 1);
    if (result != 0)
    {
        E_Print("Can't set immediate mode! %d\n", result);
        return EXIT_FAILURE;
    }
    // TODO: stabilire un buffer size, non sono sicuro serva con la immediate mode

    return EXIT_SUCCESS;
}
int activateHandle(pcap_t *handle)
{
    const int result = pcap_activate(handle);
    if (result > 0)
    {
        D_Print("Handle activated with Warning %d\n", result);
    } else if (result < 0)
    {
        E_Print("Can't cativate handle! %d\n", result);
        pcap_perror(handle, "activate");
        return EXIT_FAILURE;
    }

    const int datalink = pcap_datalink(handle);
    D_Print("The datalink for this handle is: %s\n", pcap_datalink_val_to_name(datalink));

    return EXIT_SUCCESS;
}
int loop(pcap_t *handle)
{
    struct pcap_pkthdr *header;
    const u_char *packet;

    sifs = findLargestSIFS(handle);
    difs = SLOT_TIME * 2 + sifs;

    D_Print("SIFS = %d\nDIFS = %d\n", sifs, difs);

    //Il non blocking è settato dentro al findSIFS


    //TODO: cambiare questo for in modo tale che esce tramite una condizione che viene data dall'esterno o da un pacchetto particolare

    State_t state = CLEAR;
    for (int i = 0; i < 200000; ++i)
    {
        const int result = pcap_next_ex(handle, &header, &packet);
        if (!result)
        {
            if (isEmpty(packetsQueue) || state != CLEAR)
                continue;
            mySleep(difs);
            //TODO: contention window
            if (!isChannelFree(handle))
                continue;
            if (sendPacket(handle))
                continue;

            state = WAIT_CTS;
        }

        if (!isForMe(packet))
        {
            mySleep(getDuration(packet));
            continue;
        }

        switch (state)
        {
            case CLEAR:
                if (!isRTS(packet))
                    continue;

                mySleep(sifs);
                if (!isChannelFree(handle))
                    continue;
                if (sendCTS(handle, packet))
                    continue;
                state = WAIT_DATA;
                break;
            case WAIT_CTS:
                if (!isCTS(packet))
                {
                    state = CLEAR;
                    break;
                }
            //TODO: mandare i dati
                mySleep(sifs);
                if (!isChannelFree(handle))
                {
                    state = CLEAR;
                    continue;
                }

                if (sendPacket(handle))
                {
                    state = CLEAR;
                    continue;
                }
                state = WAIT_ACK;

                break;
            case WAIT_DATA:
                if (!isDATA(packet))
                {
                    state = CLEAR;
                    break;
                }
            //TODO: mandare l'ack
                mySleep(sifs);
                if (!isChannelFree(handle))
                {
                    state = CLEAR;
                    continue;
                }
                if (sendPacket(handle))
                {
                    state = CLEAR;
                    continue;
                }
                state = CLEAR;

                break;
            case WAIT_ACK:
                if (!isACK(packet))
                {
                    state = CLEAR;
                    break;
                }
            //TODO: contrassegnare il messaggio come inviato
                state = CLEAR;
                break;
        }
    }

    return EXIT_SUCCESS;
}

void cleanPcap(pcap_t *handle)
{
    pcap_close(handle);
}
