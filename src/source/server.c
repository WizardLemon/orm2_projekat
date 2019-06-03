#include <stdio.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <pcap/pcap.h>
#include <pthread.h>
#include "../header/server.h"
#include "../header/utilities.h"

#define PACKET_ARRAY_MAX_LEN 100

#ifdef _MSC_VER
    /* WINDOWS COMPATIBILITY BEGIN */
    #define _CRT_SECURE_NO_WARNINGS
    #include <windows.h>
    /* WINDOWS COMPATIBILITY END */
#else
    /* LINUX COMPATIBILITY BEGIN */
    #include <netinet/in.h>
    #include <pthread.h>
    /* LINUX COMPATIBILITY END */
#endif


int main(int argc, char *argv[]) {
    pcap_if_t * devices;        	//List of network interfaces
    pcap_if_t * current_device; 	//Current network interface
    pcap_t* device_handle;
    packet_t recieving_packets[PACKET_ARRAY_MAX_LEN], sending_packets[PACKET_ARRAY_MAX_LEN]; //PACKET_ARRAY
    char errorMsg[PCAP_ERRBUF_SIZE + 1];
	
	unsigned int netmask;
    char filter_exp[] = "";

    unsigned char i, j, k; //iterators
    unsigned char number_of_sending = atoi(argv[1]);

    // Retrieve the device list
    if(pcap_findalldevs(&devices, errorMsg) == -1)
    {
        printf("Error in pcap_findalldevs: %s\n", errorMsg);
        return -1;
    }

    current_device = select_device(devices);
    
    // Check if device is valid
	if (current_device == NULL) 
	{
		pcap_freealldevs(devices);
		return -1;
	}
	
	// Open the capture device
    if ((device_handle = pcap_open_live(current_device->name,		// name of the device
    									65536,						// portion of the packet to capture (65536 guarantees that the whole 																		   packet will be captured on all the link layers)
    									1,							// promiscuous mode
    									2000,						// read timeout
        								errorMsg					// buffer where error message is stored
    									)) == NULL)
    {
        printf("\nUnable to open the adapter. %s is not supported by libpcap/WinPcap\n", current_device->name);
        pcap_freealldevs(devices);
        return -1;
    }
    
    // Check the link layer. We support only Ethernet for simplicity.
    if (pcap_datalink(device_handle) != DLT_EN10MB)
    {
        printf("\nThis program works only on Ethernet networks.\n");
        return -1;
    }
    
    // TODO
    // Podesiti filter i primiti paket
	
#ifdef _MSC_VER


#else
    /* LINUX COMPATIBILITY BEGIN */
    pthread_t sending_thread[2]; //One sending thread is for WiFi, other is for internet
    pthread_t recieving_thread[2]; //One receiving thread is for WiFi, other is for internet
    /* LINUX COMPATIBILITY END */
#endif


    return 0;
}
