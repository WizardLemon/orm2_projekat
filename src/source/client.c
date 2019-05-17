#include <stdio.h>
#include <stdlib.h>
#include "../header/client.h"
#include "../header/utilities.h"

#define PACKET_ARRAY_MAX_LEN 100

#ifdef _MSC_VER
    /* WINDOWS COMPATIBILITY BEGIN */
    #define _CRT_SECURE_NO_WARNINGS
    /* WINDOWS COMPATIBILITY END */
#else
    /* LINUX COMPATIBILITY BEGIN */
    #include <netinet/in.h>
    #include <pthread.h>
    /* LINUX COMPATIBILITY END */
#endif

/* CONSTANT MACROS BEGIN */
#define PACKET_ARRAY_MAX_LEN 100
/* CONSTANT MACROS END */

int main(int argc, char *argv[]) {
    pcap_if_t * devices;        //List of network interfaces
    pcap_if_t * current_device; //Current network interface
    packet_t recieving_packets[PACKET_ARRAY_MAX_LEN], sending_packets[PACKET_ARRAY_MAX_LEN]; //PACKET_ARRAY
    char errorMsg[PCAP_ERRBUF_SIZE + 1];

    unsigned char i, j, k; //iterators
    unsigned char number_of_sending = atoi(argv[1]);

    // Retrieve the device list
    if(pcap_findalldevs(&devices, errorMsg) == -1)
    {
        printf("Error in pcap_findalldevs: %s\n", errorMsg);
        return -1;
    }

    current_device = select_device(devices);
#ifdef _MSC_VER

#else
    /* LINUX COMPATIBILITY BEGIN */
    pthread_t sending_thread[2]; //One sending thread is for WiFi, other is for internet
    pthread_t recieving_thread[2]; //One receiving thread is for WiFi, other is for internet
    /* LINUX COMPATIBILITY END */
#endif

    return 0;
}
