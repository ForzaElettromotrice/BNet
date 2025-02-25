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

	loopPcap(handle);
	for (int i = 0; i < 10; ++i)
	{
		mySleep(1000000);
		MyRadiotap_t radiotap;
		MyBeacon_t beacon;
		buildRadiotap(&radiotap);
		buildBeacon(&beacon, "Daje roma daje", 14);

		u_char packet[sizeof(MyRadiotap_t) + sizeof(MyBeacon_t)];
		memcpy(packet, &radiotap, sizeof(MyRadiotap_t));
		memcpy(packet + sizeof(MyRadiotap_t), &beacon, sizeof(MyBeacon_t));

		addPacket(Beacon, &packet, sizeof(MyRadiotap_t) + sizeof(MyBeacon_t));
	}
	stopPcap();
	return EXIT_SUCCESS;
}

int main()
{
#ifdef Debug
	D_Print("Launched in Debug Mode!\n");
#endif

	// u_char packet[] = {0xb4, 0x00, 0x00, 0x00, 0x24, 0xec, 0x99, 0xd0, 0x92, 0x6d, 0x24, 0xec, 0x99, 0xd0, 0x92, 0x6d};
	// uint32_t checksum = crc32(packet, sizeof(packet));
	// printf("%d\n", checksum);
	// return 0;


	pcap_t *handle;
	if (init(&handle))
		return EXIT_FAILURE;

	int out = mainLoop(handle);

	clean(handle);
	return out;
}
