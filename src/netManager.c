#include "netManager.h"

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
	// TODO: Vedere tutte le opzioni e settarle
	// TODO:vedere se la monitor mode si può attivare e attivarla
	// TODO: delay (packet buffer timeout) fra una lettura di un pacchetto e l'altra, non so se metterlo
	// TODO: in caso si può mettere la immediate mode
	// TODO: stabilire un buffer size, non sono sicuro serva con la immediate mode
	printf("Implementami (setHandleOptions)\n");
	return EXIT_SUCCESS;
}

void cleanPcap(pcap_t *handle)
{
	pcap_close(handle);
}
