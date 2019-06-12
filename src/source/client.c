#include <stdio.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <pcap/pcap.h>
#include <pthread.h>
#include "../header/client.h"
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
    pthread_mutex_t sending_mutex;
    /* LINUX COMPATIBILITY END */
#endif

/* CONSTANT MACROS BEGIN */
#define PACKET_ARRAY_MAX_LEN 500
/* CONSTANT MACROS END */

/* GLOBAL VARIABLES BEGIN */
packet_t sending_packets[PACKET_ARRAY_MAX_LEN];
unsigned int number_of_packets_for_sending = 0;
unsigned char packet_sequence[PACKET_ARRAY_MAX_LEN]; //Ovo indeksiras sa sekvencom paketa
const unsigned char home_MAC[6] = {0xfc, 0xaa, 0x14, 0x61, 0x49, 0xbc};
const unsigned char dest_MAC[6] = {0xfc, 0xaa, 0x14, 0x61, 0x49, 0xbc};
const unsigned char home_ip[4] = {192, 168, 1, 6};
const unsigned char dest_ip[4] = {192, 168, 1, 6};
const unsigned short home_port = 6000;
const unsigned short dest_port = 6000;
/* GLOBAL VARIABLES END */

int client_receive_ack_packet(pcap_t * device, packet_t * packet_receiving_array) {
    unsigned char result = 0;
    struct pcap_pkthdr ** pkt_header; //Ovo se koristi za statistiku;
    const u_char ** pcap_temp_data; //Ovo treba zameniti tako da se koristi packet_receiving_array
    while((result = pcap_next_ex(device, pkt_header, pcap_temp_data)) >= 0) {
        //Cuvanje paketa i njihova obrada
    }
}

//Ova funkcija radi za individualni paket. Nju pozivas u okviru funkcije za nit
int prepare_packet_for_sending(FILE * file, packet_t * preparing_packet) { //treba nam broj sekvence udp paketa da bismo ga znali prepoznati u client_receive_ack_packets
    unsigned char result = 0;
    unsigned char ret_val = 0;
    unsigned char data_read_number;

    if((data_read_number = fread(preparing_packet->data, sizeof(char), PACKET_DATA_LEN, file)) < PACKET_DATA_LEN) {
        ret_val = -1; //STIGLI SMO DO KRAJA FAJLA
    }

    ethernet_header_t eth = create_eth_header(home_MAC, dest_MAC);
    ip_header_t iph = create_ip_header(data_read_number, home_ip, dest_ip);
    udp_header_t udph = create_udp_header(home_port, dest_port, data_read_number);

    init_packet_headers(preparing_packet, &eth, &iph, &udph);

    return ret_val;
}

void* thread_function_sending(void* sending_device) {
    while(number_of_packets_for_sending > 0) {
#ifdef _WIN32

#else
        pthread_mutex_lock(&sending_mutex); //Zakljucavamo zato sto ne zelimo da istovremeno i wifi i ethernet pristupe sending_packets nizu
        if(pcap_sendpacket((pcap_t *)sending_device,
                           (char*)&sending_packets[number_of_packets_for_sending],
                           sizeof(packet_t))) {
        printf("Sending error. Sending stoped");
        return NULL;

        }
        pthread_mutex_unlock(&sending_mutex); //Zakljucavamo zato sto ne zelimo da istovremeno i wifi i ethernet pristupe sending_packets nizu
#endif
    }
}

/*
int load_txt_for_sending(FILE * file_name, packet_t * packet_array) {
    FILE * file;
    int i = 0;
    if((file = fopen(file_name, "r")) == NULL) {
        printf("File %s could not be opened for reading.", file_name);
        return -1;
    }
    while(fread(packet_array[i]->data, sizeof(char), PACKET_DATA_LEN, file) >= PACKET_DATA_LEN) { //CIM PROCITAMO MANJE OD PACKET_DATA_LEN TO ZNACI DA SMO STIGLI DO KRAJA
        if(++i > PACKET_ARRAY_MAX_LEN) {
            printf("File %s is too large to be sent. ", file_name);
            return -1; //ne saljemo fajl uopste posto ga nismo celog uspeli ucitati
        }
    }
    return ++i; //VRATI BROJ PAKETA KOJI SU NAPUNJENI U packet_array
}*/


int main(int argc, char *argv[]) {

    pcap_if_t * ethernet_device_item, * wifi_device_item; //Ethernet interface, Wifi interface
    pcap_if_t * devices;        //List of network interfaces
    pcap_t * ethernet_device; //Ethernet interface
    pcap_t * wifi_device;  //Wifi interface

    FILE * data_file;

    packet_t recieving_packet, sending_packet; //PACKET_ARRAY
    char errorMsg[PCAP_ERRBUF_SIZE + 1];
    
    unsigned int current_packet_sequence = 0;
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
    printf("F\n");

    ethernet_device_item = select_device(devices);
    printf("E\n");
    wifi_device_item = select_device(devices);


    /*/*
    current_device = select_device(devices);
    
    // Check if device is valid
	if (current_device == NULL)
	{
		pcap_freealldevs(devices);
		return -1;
    }
    */
    printf("UPomoc\n");
    // Open the ethernet device for sending
    if ((ethernet_device = pcap_open_live(ethernet_device_item->name,		// name of the device
    									65536,						// portion of the packet to capture (65536 guarantees that the whole 																		   packet will be captured on all the link layers)
                                        0,							// non promiscuous mode
                                        MINIMUM_TIMEOUT_TIME,						// read timeout
        								errorMsg					// buffer where error message is stored
    									)) == NULL)
    {
        printf("%s", errorMsg);
        printf("\nUnable to open the %s ethernet adapter.", ethernet_device_item->name);
        pcap_freealldevs(devices);
        return -1;
    }
    printf("Cernobil\n");
    if(pcap_datalink(ethernet_device) != DLT_EN10MB) 	{
        printf("\nChoose a valid Ethernet based device.\n");
        pcap_freealldevs(devices);
        return -1;
    }

    //Open the WiFi device for sending
    if ((wifi_device = pcap_open_live(wifi_device_item->name,		// name of the device
                                        65536,						// portion of the packet to capture (65536 guarantees that the whole 																		   packet will be captured on all the link layers)
                                        0,							// promiscuous mode
                                        MINIMUM_TIMEOUT_TIME,						// read timeout
                                        errorMsg					// buffer where error message is stored
                                        )) == NULL)
    {
        printf("%s", errorMsg);
        printf("\nUnable to open the %s WiFi adapter.", wifi_device_item->name);
        pcap_freealldevs(devices);
        return -1;
    }
    printf("A");
    //Checking if WiFi device was choosen
    if(pcap_datalink(wifi_device) != DLT_IEEE802_11) 	{
        printf("\nChoose a valid WiFi based device.\n");
        pcap_freealldevs(devices);
        return -1;
    }
    //Open file for reading
    if((data_file = fopen("random.txt", "r")) == NULL) {
        return -1;
    }
    printf("B");
    while(prepare_packet_for_sending(data_file, &sending_packet) > 0) { //ova funkcija vraca -1 kada je stigla do end of file
        sending_packet.packet_number = current_packet_sequence;
        sending_packets[current_packet_sequence] = sending_packet;
        current_packet_sequence++;
    }
    number_of_packets_for_sending = current_packet_sequence + 1;

#ifdef _WIN32

#else
    /* LINUX COMPATIBILITY BEGIN */
    pthread_mutex_init(&sending_mutex, NULL);
    pthread_t sending_thread[2]; //One sending thread is for WiFi, other is for internet
    pthread_t recieving_thread[2]; //One receiving thread is for WiFi, other is for internet
    pthread_create(&sending_thread[0], NULL, thread_function_sending, wifi_device);
    pthread_create(&sending_thread[1], NULL, thread_function_sending, ethernet_device);
    /* LINUX COMPATIBILITY END */
#endif

    return 0;
}
