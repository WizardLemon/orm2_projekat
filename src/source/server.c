#include <stdio.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <pcap/pcap.h>
#include <pthread.h>
#include "../header/server.h"
#include "../header/utilities.h"

#ifdef _MSC_VER
    /* WINDOWS COMPATIBILITY BEGIN */
    #define _CRT_SECURE_NO_WARNINGS
    #include <windows.h>
    /* WINDOWS COMPATIBILITY END */
#else
    /* LINUX COMPATIBILITY BEGIN */
    #include <netinet/in.h>
    #include <pthread.h>
    //MUTEX MORA BITI OVDE, AKO SE JA DOBRO SECAM
    /* LINUX COMPATIBILITY END */
#endif

/* CONSTANT MACROS BEGIN */
#define PACKET_ARRAY_MAX_LEN 500
/* CONSTANT MACROS END */

/* GLOBAL VARIABLES BEGIN */
packet_t recieved_packets[PACKET_ARRAY_MAX_LEN];
unsigned int number_of_packets_recieved = 0;
unsigned char packet_sequence[PACKET_ARRAY_MAX_LEN]; //Ovo indeksiras sa sekvencom paketa
const unsigned char home_MAC[6] = {0x08, 0x00, 0x27, 0x6a, 0x1e, 0x78};	// ZAPAMTI DA NAMESTIS NA SVOJ IP I MAC
const unsigned char dest_MAC[6] = {0x08, 0x00, 0x27, 0x6a, 0x1e, 0x78};
const unsigned char home_ip[4] = {192, 168, 1, 1};
const unsigned char dest_ip[4] = {192, 168, 1, 1};
const unsigned short home_port = 6000;
const unsigned short dest_port = 6000;
/* GLOBAL VARIABLES END */

int main(int argc, char *argv[]) {

    pcap_if_t * ethernet_device_item, * wifi_device_item; //Ethernet interface, Wifi interface
    pcap_if_t * devices;        	//List of network interfaces
    pcap_t * ethernet_device; //Ethernet interface
    pcap_t * wifi_device;  //Wifi interface
    
    packet_t recieving_packets[PACKET_DATA_LEN], sending_packets[PACKET_DATA_LEN]; //PACKET_ARRAY
    
    struct bpf_program fcode;
    char filter[] = "udp and dst port 6000";
    
    FILE * data_file;

    char errorMsg[PCAP_ERRBUF_SIZE + 1];
	
	unsigned int netmask;
    char filter_exp[] = "";

    unsigned char i, j, k; //iterators

    // Retrieve the device list
    if(pcap_findalldevs(&devices, errorMsg) == -1)
    {
        printf("Error in pcap_findalldevs: %s\n", errorMsg);
        return -1;
    }

    //OVO MORA DA STOJI ZATO STO NAM TREBAJU DVA UREDJAJA ZA SLANJE
    //JEDAN ZA WIFI DRUGI ZA ETHERNET
    printf("Izaberite odgovarajuci ethernet interfejs\n");
    ethernet_device_item = select_device(devices);
    
    printf("Izaberite odgovarajuci WiFi interfejs\n");
    wifi_device_item = select_device(devices);

    // Open the ethernet device for sending
    if ((ethernet_device = pcap_open_live(ethernet_device_item->name,		// name of the device
    									65536,						// portion of the packet to capture (65536 guarantees that the whole 																		   packet will be captured on all the link layers)
                                        0,							// non promiscuous mode
                                        MINIMUM_TIMEOUT_TIME,		// read timeout
        								errorMsg					// buffer where error message is stored
    									)) == NULL)
    {
        printf("%s", errorMsg);
        printf("\nUnable to open the %s ethernet adapter.", ethernet_device_item->name);
        pcap_freealldevs(devices);
        return -1;
    }

	//Checking if ethernet device was chosen
    if(pcap_datalink(ethernet_device) != DLT_EN10MB) 	{
        printf("\nChoose a valid Ethernet based device.\n");
        pcap_freealldevs(devices);
        return -1;
    }
    
    // Set netmask
#ifdef _WIN32
	if(ethernet_device_item->addresses != NULL)
		/* Retrieve the mask of the first address of the interface */
		netmask=((struct sockaddr_in *)(ethernet_device_item->addresses->netmask))->sin_addr.S_un.S_addr;
	else
		/* If the interface is without addresses we suppose to be in a C class network */
		netmask=0xffffff;
#else
    if (!ethernet_device_item->addresses->netmask)
        netmask = 0;
    else
        netmask = ((struct sockaddr_in *)(ethernet_device_item->addresses->netmask))->sin_addr.s_addr;
#endif

	// Compile the filter
	if (pcap_compile(ethernet_device, &fcode, filter, 1, netmask) < 0)
	{
		 printf("\n Unable to compile the packet filter. Check the syntax.\n");
		 return -1;
	}

	// Set the filter
	if (pcap_setfilter(ethernet_device, &fcode) < 0)
	{
		printf("\n Error setting the filter.\n");
		return -1;
	}

    //Open the WiFi device for sending
    if ((wifi_device = pcap_open_live(wifi_device_item->name,		// name of the device
                                        65536,						// portion of the packet to capture (65536 guarantees that the whole 																		   packet will be captured on all the link layers)
                                        0,							// promiscuous mode
                                        MINIMUM_TIMEOUT_TIME,		// read timeout
                                        errorMsg					// buffer where error message is stored
                                        )) == NULL)
    {
        printf("%s", errorMsg);
        printf("\nUnable to open the %s WiFi adapter.", wifi_device_item->name);
        pcap_freealldevs(devices);
        return -1;
    }
    
    printf("A");
    
    //Checking if WiFi device was chosen
    if(pcap_datalink(wifi_device) != DLT_IEEE802_11) 	{
        printf("\nChoose a valid WiFi based device.\n");
        pcap_freealldevs(devices);
        return -1;
    }
    
    // Set netmask
#ifdef _WIN32
	if(wifi_device_item->addresses != NULL)
		/* Retrieve the mask of the first address of the interface */
		netmask=((struct sockaddr_in *)(wifi_device_item->addresses->netmask))->sin_addr.S_un.S_addr;
	else
		/* If the interface is without addresses we suppose to be in a C class network */
		netmask=0xffffff;
#else
    if (!wifi_device_item->addresses->netmask)
        netmask = 0;
    else
        netmask = ((struct sockaddr_in *)(wifi_device_item->addresses->netmask))->sin_addr.s_addr;
#endif

	// Compile the filter
	if (pcap_compile(wifi_device, &fcode, filter, 1, netmask) < 0)
	{
		 printf("\n Unable to compile the packet filter. Check the syntax.\n");
		 return -1;
	}

	// Set the filter
	if (pcap_setfilter(wifi_device, &fcode) < 0)
	{
		printf("\n Error setting the filter.\n");
		return -1;
	}


#ifdef _WIN32

#else
    /* LINUX COMPATIBILITY BEGIN */
    pthread_t sending_thread[2]; //One sending thread is for WiFi, other is for internet
    pthread_t recieving_thread[2]; //One receiving thread is for WiFi, other is for internet
    /* LINUX COMPATIBILITY END */
#endif

    return 0;
}
