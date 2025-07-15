//
// Created by f3m on 28/05/25.
//


#include <pcap/pcap.h>
#include <queue.h>
#include <netManager.h>
#include <logger.h>
#include <netUtils.h>
#include <structures.h>
#include <unistd.h>
#include <sys/wait.h>
#include <pthread.h>
#include <string.h>
#include <errno.h>

Context_t context = {};

int setMonitor(const char *interfaceName)
{
    const pid_t pid = fork();
    if (pid < 0)
    {
        logE(context.err, "fork: %s\n", strerror(errno));
        return EXIT_FAILURE;
    }
    if (pid == 0)
    {
        execlp("sh", "sh", SETMONITOR_SCRIPT_PATH, interfaceName, (char *) NULL);
        logE(context.err, "execlp: %s\n", strerror(errno));
        return EXIT_FAILURE;
    }
    int status;
    if (waitpid(pid, &status, 0) == -1)
    {
        logE(context.err, "waitpid: %s\n", strerror(errno));
        return EXIT_FAILURE;
    }
    if (!(WIFEXITED(status)))
        return EXIT_FAILURE;

    const int exit_code = WEXITSTATUS(status);
    if (exit_code != 0)
        return EXIT_FAILURE;

    return EXIT_SUCCESS;
}
int setHandleOptions()
{
    const int result = pcap_set_immediate_mode(context.handle, 1);
    if (result != 0)
    {
        logE(context.err, "Can't set immediate mode! %d\n", result);
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}
int setMyAddr(const char *interfaceName)
{
    char path[256];
    u_char text[17];

    sprintf(path, "/sys/class/net/%s/address", interfaceName);
    FILE *f = fopen(path, "r");
    if (!f)
    {
        logE(context.err, "fopen: %s\n", strerror(errno));
        return EXIT_FAILURE;
    }

    fread(text, sizeof(u_char), 17, f);
    fclose(f);

    for (int i = 0; i < 17; i += 3)
    {
        const char t[] = {text[i], text[i + 1]};
        context.myAddr[i / 3] = strtol(t, NULL, 16);
    }
    return EXIT_SUCCESS;
}

int sendPacket(pcap_t *handle)
{
    size_t size;
    void *packet;
    if (popQueue(context.packetsQueue, &packet, &size))
    {
        logE(context.err, "Error popping the queue!\n");
        return EXIT_FAILURE;
    }
    const int result = pcap_inject(handle, packet, size);
    if (result == PCAP_ERROR)
    {
        pushFirstQueue(packet, size, context.packetsQueue);
        logE(context.err, "inject: %s\n", pcap_geterr(handle));
        return EXIT_FAILURE;
    }

    free(packet);
    return EXIT_SUCCESS;
}
void handlePacket(const struct pcap_pkthdr *header, const u_char *packet)
{
    if (context.callback == NULL)
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
            logE(context.err, "malloc: %s\n", strerror(errno));
            return;
        }
        memcpy(finalData, data, tagLen);
        context.callback(Beacon, tagLen, finalData, context.usrData);
    }
}

int initPcap(FILE *err, FILE *debug)
{
    char errbuf[PCAP_ERRBUF_SIZE];
    if (pcap_init(PCAP_CHAR_ENC_LOCAL, errbuf))
    {
        logE(err, "Pcap init failed: %s\n", errbuf);
        return EXIT_FAILURE;
    }

    context.err = err;
    context.debug = debug;

    if (initQueue(&context.packetsQueue))
    {
        logE(err, "Error while initiating the packets queue\n");
        return EXIT_FAILURE;
    }

    context.sifs = 30;
    context.difs = SLOT_TIME * 2 + context.sifs;
    context.handle = NULL;
    context.callback = NULL;
    context.usrData = NULL;
    context.thread = 0;
    context.looping = false;

    return EXIT_SUCCESS;
}
void cleanPcap()
{
    pcap_close(context.handle);
    cleanQueue(context.packetsQueue);
    if (context.looping)
        stopPcap();
}

int createHandle(const char *interfaceName)
{
    char errbuf[PCAP_ERRBUF_SIZE];

    context.handle = pcap_create(interfaceName, errbuf);
    if (!context.handle)
    {
        logE(context.err, "pcap_create: %s\n", errbuf);
        return EXIT_FAILURE;
    }

    if (setMonitor(interfaceName))
        return EXIT_FAILURE;

    if (setHandleOptions())
        return EXIT_FAILURE;

    if (setMyAddr(interfaceName))
        return EXIT_FAILURE;

    return EXIT_SUCCESS;
}
void setCallback(void (*callback)(PacketType_t, size_t, const u_char *, void *), void *userData)
{
    context.callback = callback;
    context.usrData = userData;
}
int activateHandle()
{
    const int result = pcap_activate(context.handle);
    if (result > 0)
    {
        logD(context.debug, "Handle activated with Warning %d\n", result);
    } else if (result < 0)
    {
        logE(context.err, "Can't cativate handle! %d\n", result);
        pcap_perror(context.handle, "activate");
        return EXIT_FAILURE;
    }

    const int datalink = pcap_datalink(context.handle);
    logD(context.debug, "The datalink for this handle is: %s\n", pcap_datalink_val_to_name(datalink));

    return EXIT_SUCCESS;
}

void addPacket(const PacketType_t type, const void *data, const size_t len)
{
    MyRadiotap_t radiotap;
    buildRadiotap(&radiotap);

    switch (type)
    {
        case Beacon:
            MyBeacon_t beacon = {};
            u_char packet[sizeof(MyRadiotap_t) + sizeof(MyBeacon_t)];

            buildBeacon(&beacon, data, len, context.myAddr);
            memcpy(packet, &radiotap, sizeof(MyRadiotap_t));
            memcpy(packet + sizeof(MyRadiotap_t), &beacon, sizeof(MyBeacon_t));

            pushQueue(packet, sizeof(packet), context.packetsQueue);
            break;
        case Data:
            logE(context.err, "Data packet not implemented yet!\n");
            break;
    }
}

void *loop(void *arg)
{
    struct pcap_pkthdr *header;
    const u_char *packet;

    // sifs = findLargestSIFS(handle);
    logD(context.debug, "SIFS = %d\tDIFS = %d\n", context.sifs, context.difs);

    //Il non blocking è settato dentro al findSIFS
    char errbuf[PCAP_ERRBUF_SIZE];
    if (pcap_setnonblock(context.handle, 1, errbuf))
    {
        logE(context.err, "Setnonblock: %s\n", errbuf);
        return (void *) EXIT_FAILURE;
    }

    while (context.looping)
    {
        const int result = pcap_next_ex(context.handle, &header, &packet);
        if (!result)
        {
            if (isEmpty(context.packetsQueue))
                continue;
            mySleep(context.difs);
            //TODO: contention window
            if (!isChannelFree(context.handle))
                continue;
            sendPacket(context.handle);
            continue;
        }

        if (!isForMe(packet, context.myAddr))
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
    context.looping = true;
    if (pthread_create(&context.thread, NULL, loop, NULL))
    {
        context.looping = false;
        logE(context.err, "Error while creating thread\n");
        return EXIT_FAILURE;
    }
    return EXIT_SUCCESS;
}
int stopPcap()
{
    context.looping = false;
    void *out;
    if (pthread_join(context.thread, &out))
    {
        logE(context.err, "Error while joining thread\n");
        return EXIT_FAILURE;
    }

    if ((size_t) out == EXIT_FAILURE)
        logE(context.err, "loop exited with code %d\n", EXIT_FAILURE);

    return EXIT_SUCCESS;
}
