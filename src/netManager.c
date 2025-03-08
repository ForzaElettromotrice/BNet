#include "netManager.h"
#include "logger.h"
#include "queue.h"
#include "parameters.h"

uint16_t sifs = 0;
uint16_t difs = 0;

Queue_t *packetsQueue;
void (*cback)(PacketType_t, size_t, u_char *);

volatile bool looping = false;
pthread_t thread;

pcap_t *handle;


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
void handlePacket(const struct pcap_pkthdr *header, const u_char *packet)
{
    if (cback == NULL)
        return;
    if (isBeacon(packet))
    {
        uint8_t tagLen;
        const char *ssid = getBeaconSSID(packet, header->len, &tagLen);

        if (tagLen != 7 || strncmp(ssid, "AutoNet", 7) != 0)
            return;

        const u_char *data = getBeaconData(packet, header->len, &tagLen);
        //TODO: controllare se c'è
        u_char *finalData = malloc(tagLen * sizeof(u_char));
        if (!finalData)
        {
            E_Print("malloc: %s\n", strerror(errno));
            return;
        }
        memcpy(finalData, data, tagLen);
        cback(Beacon, tagLen, finalData);
    }
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
    //TODO: migliorare questa funzione, mettere un limite temporale nel quale se non trova dati lo decide di suo
    //TODO: e inoltre va migliorata la logica secondo cui viene calcolato sto tempo
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

    cback = NULL;

    return EXIT_SUCCESS;
}
void cleanPcap()
{
    pcap_close(handle);
    cleanQueue(packetsQueue);
    cback = NULL;
}

int setHandleOptions()
{
    const int result = pcap_set_immediate_mode(handle, 1);
    if (result != 0)
    {
        E_Print("Can't set immediate mode! %d\n", result);
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}
int createHandle(const char *interfaceName)
{
    char errbuf[PCAP_ERRBUF_SIZE];

    handle = pcap_create(interfaceName, errbuf);
    if (!handle)
    {
        E_Print("pcap_create: %s\n", errbuf);
        return EXIT_FAILURE;
    }

    if (setHandleOptions())
        return EXIT_FAILURE;

    return EXIT_SUCCESS;
}
void setCallback(void (*callback)(PacketType_t, size_t, u_char *))
{
    cback = callback;
}
int activateHandle()
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

void addPacket(const PacketType_t type, const void *data, const size_t len)
{
    MyRadiotap_t radiotap;
    buildRadiotap(&radiotap);

    switch (type)
    {
        case Beacon:

            MyBeacon_t beacon;
            u_char packet[sizeof(MyRadiotap_t) + sizeof(MyBeacon_t)];

            buildBeacon(&beacon, data, len);
            memcpy(packet, &radiotap, sizeof(MyRadiotap_t));
            memcpy(packet + sizeof(MyRadiotap_t), &beacon, sizeof(MyBeacon_t));

            pushQueue(packet, sizeof(packet), packetsQueue);
            break;
        case Data:
            break;
    }
}

void *loop()
{
    struct pcap_pkthdr *header;
    const u_char *packet;

    // sifs = findLargestSIFS(handle);
    sifs = 30;
    difs = SLOT_TIME * 2 + sifs;

    D_Print("SIFS = %d\nDIFS = %d\n", sifs, difs);

    //Il non blocking è settato dentro al findSIFS
    char errbuf[PCAP_ERRBUF_SIZE];
    if (pcap_setnonblock(handle, 1, errbuf))
    {
        E_Print("Setnonblock: %s\n", errbuf);
        return (void *) EXIT_FAILURE;
    }

    looping = true;
    while (looping)
    {
        const int result = pcap_next_ex(handle, &header, &packet);
        if (!result)
        {
            if (isEmpty(packetsQueue))
                continue;
            mySleep(difs);
            //TODO: contention window
            if (!isChannelFree(handle))
                continue;
            if (sendPacket(handle))
                continue;
        }

        if (!isForMe(packet))
        {
            mySleep(getDuration(packet));
            continue;
        }

        handlePacket(header, packet);
    }
    return (void *) EXIT_SUCCESS;
}
int loopPcap()
{
    if (pthread_create(&thread, NULL, loop, NULL))
    {
        E_Print("Error while creating thread\n");
        return EXIT_FAILURE;
    }
    return EXIT_SUCCESS;
}

int stopPcap()
{
    looping = false;
    void *out;
    if (pthread_join(thread, &out))
    {
        E_Print("Error while joining thread\n");
        return EXIT_FAILURE;
    }

    if (*(int *) out == EXIT_FAILURE)
        E_Print("loop exited with code %d\n", EXIT_FAILURE);

    return EXIT_SUCCESS;
}
