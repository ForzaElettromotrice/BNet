#include "main.h"
#include "netUtility.h"

int init(pcap_t **handle)
{
	if(initPcap())
		return EXIT_FAILURE;
	if(createHandle(handle))
		return EXIT_FAILURE;
	if(setHandleOptions(*handle))
		return EXIT_FAILURE;

	return EXIT_SUCCESS;
}

void clean(pcap_t *handle)
{
	cleanPcap(handle);
}

int mainLoop(pcap_t *handle)
{
	// TODO: fare il loop di controllo dei pacchetti
    if(activateHandle(handle))
        return EXIT_FAILURE;
    loop(handle);    
	return EXIT_SUCCESS;
}

int main()
{
	pcap_t *handle;
	if(init(&handle))
		return EXIT_FAILURE;

	int out = mainLoop(handle);

//    struct timespec duration;
  //  duration.tv_sec = 0;
    //duration.tv_nsec = 10;
    //struct timespec start;
    //struct timespec end;
    //clock_gettime(CLOCK_MONOTONIC, &start);
    //for(int i = 0; i < 20000; ++i)
   // {
    //    clock_gettime(CLOCK_MONOTONIC, &end);
     //   if(end.tv_sec - start.tv_sec == 0 && end.tv_nsec - start.tv_nsec > 10000)
      //  {
//            printf("%d\n", i);
    //        break;
  //      }
        //printf("Time: %ld ns\n", end.tv_nsec - start.tv_nsec);
        //clock_gettime(CLOCK_MONOTONIC, &start);
    //}
    clean(handle);
	return out;
}
