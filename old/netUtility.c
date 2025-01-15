#include "netUtility.h"


int getAddr(struct sockaddr *sa, char **addr)
{
	*addr = malloc(NI_MAXHOST * sizeof(char));

	if(!getnameinfo(sa, sizeof(struct sockaddr_storage), *addr, NI_MAXHOST, NULL, 0, NI_NUMERICHOST) == 0)
	{
		//E_Print("getnameinfo: %s\n", strerror(errno));
		free(*addr);
		return EXIT_FAILURE;
	}
	return EXIT_SUCCESS;
}
void enumerateDevices(pcap_if_t *device)
{
	for(int i = 0 ; device->next != NULL; device = device->next)
	{
		printf("----------DEVICE %d----------\n", i++);
		printf(BOLD "Name:" RESET " %s\n", device->name);
		if(!device->addresses)
			continue;
		for(pcap_addr_t *address = device->addresses; address->next != NULL; address = address->next)
		{
			char *addr;
			if(getAddr(address->addr, &addr))
				continue;

			printf(BOLD "Address:" RESET " %s\n", addr);
			free(addr);

		}
	}
}

int getDevices(pcap_if_t **device)
{
	char errBuff[PCAP_ERRBUF_SIZE];

	if(pcap_findalldevs(device, errBuff))
	{
		E_Print("Device not found: %s\n", errBuff);
		return EXIT_FAILURE;
	}

	return EXIT_SUCCESS;
}

void cleanDevices(pcap_if_t *device)
{
	pcap_freealldevs(device);
}
