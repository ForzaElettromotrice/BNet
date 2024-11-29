#include "netManager.h"

void packetHandler(u_char *user, const struct pcap_pkthdr *h, const u_char *bytes) 
{
    printf("--------------------\n");
    printf("Timestamp: %ld\n", h->ts.tv_sec);
    printf("Caplen: %d\n", h->caplen);
    printf("Len: %d\n", h->len);
    printf("User: %s\n", user);
    for (int i = 0;i < h->len; i++) 
    {
        printf("%02x ", bytes[i]);
    }
    printf("\n");
}

int initPcap()
{	
  char errbuf[PCAP_ERRBUF_SIZE];

	if(pcap_init(PCAP_CHAR_ENC_LOCAL, errbuf))
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
	if(!*handle)
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
    if(result != 0)
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
    if(result > 0)
    {
        printf("Handle activated with Warning %d\n", result);
    }
    else if (result < 0) 
    {
        printf("Can't cativate handle! %d\n", result);
        pcap_perror(handle, "activate");
        return EXIT_FAILURE;
    }

    int datalink = pcap_datalink(handle);
    printf("Datalink: %s\n", pcap_datalink_val_to_name(datalink));

    return EXIT_SUCCESS;
}

int loop(pcap_t *handle)
{
    pcap_loop(handle, 5, packetHandler, "test");

    return EXIT_SUCCESS;
}

void cleanPcap(pcap_t *handle)
{
	pcap_close(handle);
}
