//
// Created by f3m on 19/04/25.
//

#include "main.h"

int counter = 0;

void callback(PacketType_t type, size_t size, u_char *data)
{
    const int number = *(int *) data;
    printf("Received packet number %d\n", number);
    counter++;
}


int mySend(const int n)
{
    for (int i = 0; i < n; ++i)
    {
        addPacket(BEACON, &i, sizeof(int));
        D_Print("Sent packet %d of %d\n", i + 1, n);
    }
    return EXIT_SUCCESS;
}
int myRecv(const int n)
{
    loopPcap();

    while (counter != n)
    {
    }

    stopPcap();
    return EXIT_SUCCESS;
}

int main(const int argc, char *argv[])
{
    if (argc != 3)
    {
        E_Print("Invalid arguments!\n" YELLOW "Usage:" RESET " BTest {recv/send} {n}\n");
        return EXIT_FAILURE;
    }

    Operation_t op;
    if (strcmp(argv[1], "recv") == 0)
    {
        op = RECEIVE;
    } else if (strcmp(argv[1], "send") == 0)
    {
        op = SEND;
    } else
    {
        E_Print("Invalid arguments!\n" YELLOW "Usage:" RESET " BTest {recv/send} {n}\n");
        return EXIT_FAILURE;
    }

    char *end;
    const int64_t n = strtol(argv[2], &end, 10);
    if (*argv[2] == '\0' || *end != '\0')
    {
        E_Print("Invalid arguments!\n" YELLOW "Usage:" RESET " BTest {recv/send} {n}\n");
        return EXIT_FAILURE;
    }

    initPcap();
    setCallback(callback);
    createHandle("wlan1");
    activateHandle();

    if (op == SEND)
    {
        mySend(n);
    } else
    {
        myRecv(n);
    }


    return EXIT_SUCCESS;
}
