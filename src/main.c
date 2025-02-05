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

	loop(handle);

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
