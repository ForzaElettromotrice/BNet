#include "main.h"

int init(pcap_t **handle)
{
	if (initPcap())
		return EXIT_FAILURE;
	if (createHandle(handle))
		return EXIT_FAILURE;
	if (setHandleOptions(*handle))
		return EXIT_FAILURE;

	return EXIT_SUCCESS;
}

void clean(pcap_t *handle)
{
	cleanPcap(handle);
}

int mainLoop(pcap_t *handle)
{
	if (activateHandle(handle))
		return EXIT_FAILURE;

	// loop(handle);
	const uint8_t frameType = CTS;
	const uint8_t flags = 0x0; //per ora non le usiamo
	const uint16_t duration = 0; //TODO: togliere il tempo di trasmissione
	u_char address[6];
	u_char packet[CTS_LENGTH];
	address[0] = 0x74;
	address[1] = 0x19;
	address[2] = 0xf8;
	address[3] = 0x11;
	address[4] = 0x12;
	address[5] = 0xed;
	memcpy(packet, &frameType, sizeof(uint8_t));
	memcpy(packet, &flags, sizeof(uint8_t));
	memcpy(packet, &duration, sizeof(uint16_t));
	memcpy(packet, address, 6);

	const uint32_t checksum = crc32(packet, CTS_LENGTH - 4);
	memcpy(packet + CTS_LENGTH - 4, &checksum, sizeof(uint32_t));

	pcap_inject(handle, packet, CTS_LENGTH);
	return EXIT_SUCCESS;
}

int main()
{
#ifdef Debug
	D_Print("Launched in Debug Mode!\n");
#endif

	pcap_t *handle;
	if (init(&handle))
		return EXIT_FAILURE;

	int out = mainLoop(handle);

	clean(handle);
	return out;
}
