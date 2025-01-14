#include "netManager.h"

uint16_t sifs = 0;
uint16_t difs = 0;


void mySleep(int usec)
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

uint16_t handleCTS(uint32_t len, const u_char *bytes)
{
    uint16_t duration = bytes[2] + bytes[3] * 16;
    const u_char *receiver = bytes + 4;
    printf("----------CTS----------\n");
    printf("Duration/ID: %d\n", duration);
    printf("Receiver: ");
    for (int i = 0; i < 5; ++i)
    {
        printf("%02x:", receiver[i]);
    }
    printf("%02x\n", receiver[5]);
    return duration;
}
uint16_t handleRTS(uint32_t len, const u_char *bytes)
{
    uint16_t duration = bytes[2] + bytes[3] * 16;
    const u_char *receiver = bytes + 4;
    const u_char *transmitter = bytes + 10;
    printf("----------RTS----------\n");
    printf("Duration/ID: %d\n", duration);
    printf("Transmitter: ");
    for (int i = 0; i < 5; ++i)
    {
        printf("%02x:", transmitter[i]);
    }
    printf("%02x\n", transmitter[5]);
    printf("Receiver: ");
    for (int i = 0; i < 5; ++i)
    {
        printf("%02x:", receiver[i]);
    }
    printf("%02x\n", receiver[5]);
    return duration;
}
uint16_t handleACK(uint32_t len, const u_char *bytes)
{
    uint16_t duration = bytes[2] + bytes[3] * 16;
    const u_char *receiver = bytes + 4;
    const u_char *transmitter = bytes + 10;
    printf("----------ACK----------\n");
    printf("Duration/ID: %d\n", duration);
    printf("Transmitter: ");
    for (int i = 0; i < 5; ++i)
    {
        printf("%02x:", transmitter[i]);
    }
    printf("%02x\n", transmitter[5]);
    printf("Receiver: ");
    for (int i = 0; i < 5; ++i)
    {
        printf("%02x:", receiver[i]);
    }
    printf("%02x\n", receiver[5]);
    return duration;
}
uint16_t handleBLOCKACK(uint32_t len, const u_char *bytes)
{
    uint16_t duration = bytes[2] + bytes[3] * 16;
    const u_char *receiver = bytes + 4;
    const u_char *transmitter = bytes + 10;
    printf("----------BLOCK ACK----------\n");
    printf("Duration: %d\n", duration);
    printf("Transmitter: ");
    for (int i = 0; i < 5; ++i)
    {
        printf("%02x:", transmitter[i]);
    }
    printf("%02x\n", transmitter[5]);
    printf("Receiver: ");
    for (int i = 0; i < 5; ++i)
    {
        printf("%02x:", receiver[i]);
    }
    printf("%02x\n", receiver[5]);
    return duration;
}
uint16_t packetHandler(const struct pcap_pkthdr *h, const u_char *bytes)
{
    //printf("--------------------\n");
    printf("Timestamp: %ld.%ld\n", h->ts.tv_sec, h->ts.tv_usec);
    //printf("Caplen: %d\n", h->caplen)
    //printf("Len: %d\n", h->len);
    //printf("User: %s\n", user);
    uint16_t radiotap_len = bytes[2] + bytes[3] * 16;
    //printf("Radiotap_len = %d\n", radiotap_len);

    uint8_t frameType = bytes[radiotap_len];
    uint8_t flags = bytes[radiotap_len + 1];
    //printf("%02x\n", frameType);
    if (frameType == CTS)
    {
        return handleCTS(h->len - radiotap_len, bytes + radiotap_len);
    }
    if (frameType == RTS)
    {
        /*uint16_t a = handleRTS(h->len - radiotap_len, bytes+radiotap_len);*/
        /*printf("Timestamp: %ld.%ld\n", h->ts.tv_sec, h->ts.tv_usec);*/
        /*return a; */
        return handleRTS(h->len - radiotap_len, bytes + radiotap_len);
    } else if (frameType == BEACON)
        printf("BEACON!\n");
    else if (frameType == ACK)
    {
        return handleACK(h->len - radiotap_len, bytes + radiotap_len);
    } else if (frameType == BLOCKACK)
    {
        return handleBLOCKACK(h->len - radiotap_len, bytes + radiotap_len);
    } else
    {
        printf("ALTRO: %02x\n", bytes[radiotap_len]);
    }
    return 0;
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
        int result = pcap_next_ex(handle, &header, &packet);
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

    long s = rtsTimestamp.tv_sec * 1000000L + rtsTimestamp.tv_usec;
    long e = ctsTimestamp.tv_sec * 1000000L + ctsTimestamp.tv_usec;

    return e - s;
}
uint16_t findLargestSIFS(pcap_t *handle)
{
    int mean = 0;
    for (int i = 0; i < DIAGNOSTIC_LENGTH; ++i)
    {
        int val = findSIFS(handle);
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
    //    int result = pcap_set_rfmon(handle, 1);
    //    if(result != 0)
    //    {
    //        E_Print("Can't set monitor mode! %d\n", result);
    //        return EXIT_FAILURE;
    //  }
    // TODO: delay (packet buffer timeout) fra una lettura di un pacchetto e l'altra, non so se metterlo
    // TODO: in caso si può mettere la immediate mode
    int result = pcap_set_immediate_mode(handle, 1);
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
    int result = pcap_activate(handle);
    if (result > 0)
    {
        D_Print("Handle activated with Warning %d\n", result);
    } else if (result < 0)
    {
        E_Print("Can't cativate handle! %d\n", result);
        pcap_perror(handle, "activate");
        return EXIT_FAILURE;
    }

    int datalink = pcap_datalink(handle);
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

    bool canSend = false;
    bool temp = false;
    for (int i = 0; i < 200000; ++i)
    {
        int result = pcap_next_ex(handle, &header, &packet);
        if (!result)
        {
            if (canSend)
            {
                if (!temp)
                {
                    temp = true;
                    printf("POSSO MANDARE!\n");
                }
            }
            mySleep(difs);
            canSend = true;
            continue;
        }
        canSend = false;
        temp = false;
        if (isForMe(packet))
        {
            //TODO: gestiscilo
            D_Print("Message for me!\n");
            continue;
        }
        if (isRTS(packet))
        {
            uint16_t duration = getDuration(packet);
            D_Print("RTS!\n");
            D_Print("Duration = %d\n", duration);
            continue;
        }
        if (isCTS(packet))
        {
            uint16_t duration = getDuration(packet);
            D_Print("CTS!\n");
            D_Print("Duration = %d\n", duration);
            mySleep(duration);
            continue;
        }
        if (isACK(packet))
        {
            D_Print("ACK!\n");
            continue;
        }
        if (isBLOCKACK(packet))
        {
            D_Print("BLOCKACK!\n");
            continue;
        }
        D_Print("Something else: %02x\n", getFrameType(packet));
    }

    return EXIT_SUCCESS;
}

void cleanPcap(pcap_t *handle)
{
    pcap_close(handle);
}
