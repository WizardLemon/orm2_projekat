#include <stdio.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <pcap/pcap.h>
#include <pthread.h>
#include <string.h>
#include "../header/client.h"
#include "../header/utilities.h"

#ifdef _MSC_VER
    /* WINDOWS COMPATIBILITY BEGIN */
    #define _CRT_SECURE_NO_WARNINGS
    #include <windows.h>
    CRITICAL_SECTION sending_mutex;      // unnamed mutex
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
unsigned int sending_sleep_time[2] = {10000, 10000};
unsigned int receiving_sleep_time[2] = {10000, 10000};
unsigned int packet_number = 0;
unsigned int packets_sent_number = 0;
unsigned char receiving_thread_number = 0;
unsigned char sending_thread_number = 0;
unsigned char packet_sent_confirmation[PACKET_ARRAY_MAX_LEN] = {0}; //Ovo indeksiras sa sekvencom paketa
const unsigned char home_MAC[6] = {0xfc, 0xaa, 0x14, 0x61, 0x49, 0xbc};
const unsigned char dest_MAC[6] = {0xfc, 0xaa, 0x14, 0x61, 0x49, 0xbc};
const unsigned char home_ip[4] = {192, 168, 1, 6};
const unsigned char dest_ip[4] = {192, 168, 1, 6};
const unsigned short home_port = 6000;
const unsigned short dest_port = 6000;
/* GLOBAL VARIABLES END */

int client_receive_ack_packet(pcap_t * device) {
    int result = 0;
    //struct pcap_pkthdr ** pkt_header; //Ovo se koristi za statistiku;
    struct pcap_pkthdr * pkt_header;
    packet_t * received_packet; //Ovo treba zameniti tako da se koristi packet_receiving_array
    if((received_packet = (packet_t*)pcap_next(device, pkt_header)) == NULL) {
        return -1;
    }

#ifdef _WIN32
    EnterCriticalSection(&sending_mutex);
    sending_packets[received_packet->packet_number] = *(received_packet);
    packet_sent_confirmation[received_packet->packet_number] = 2; //Primljen je ack paket, ne treba ponovo slati
    LeaveCriticalSection(&sending_mutex);
#else
    pthread_mutex_lock(&sending_mutex);
    sending_packets[received_packet->packet_number] = *(received_packet);
    packet_sent_confirmation[received_packet->packet_number] = 2; //Primljen je ack paket, ne treba ponovo slati
    pthread_mutex_unlock(&sending_mutex);
//    while((result = pcap_next_ex(device, pkt_header, pcap_temp_data)) >= 0) {
#endif
//    }
    return received_packet->packet_number; //
}

#ifdef _WIN32
DWORD WINAPI thread_function_receive(void* device) {
#else
void* thread_function_receive(void* device) {
#endif
    int packet_received_number = -1;
    unsigned char received_error_number = 0;
    unsigned char this_thread_number = receiving_thread_number++;

    while(1) {
#ifdef _WIN32
        Sleep(receiving_sleep_time[this_thread_number]/1000);
#else
        usleep(receiving_sleep_time[this_thread_number]);
#endif
        if((packet_received_number = client_receive_ack_packet((pcap_t*)device)) < 0) {
            printf("Error while receiving next ACK packet on thread %d.\n", this_thread_number);
//            if((receiving_sleep_time[this_thread_number]*=2) > RECEIVE_FAIL_ATTEMPT_CLIENT) {
//                printf("Receiving ACK packets failed too many times by thread %d. Stoping thread.\n", received_error_number);
//                return NULL;
//            }
        }
        /* else {
            printf("ACK package %d received by thread %d.\n", packet_received_number, this_thread_number);
            pthread_mutex_lock(&sending_mutex);
            packet_sent_confirmation[packet_received_number] = 2; //paket je poslat i potvrdjen, zato stavljamo 2
            pthread_mutex_unlock(&sending_mutex);
        }*/
    }
}

//Ova funkcija radi za individualni paket. Nju pozivas u okviru funkcije za nit
int prepare_packet_for_sending(FILE * file, packet_t * preparing_packet) { //treba nam broj sekvence udp paketa da bismo ga znali prepoznati u client_receive_ack_packets
    unsigned char result = 0;
    int ret_val = 0;
    unsigned char data_read_number;

    if((data_read_number = fread(preparing_packet->data, sizeof(char), PACKET_DATA_LEN, file)) < PACKET_DATA_LEN) {
        printf("End of file reached.\n");
        ret_val = -1; //STIGLI SMO DO KRAJA FAJLA
    }

    ethernet_header_t eth = create_eth_header(home_MAC, dest_MAC);
    ip_header_t iph = create_ip_header(data_read_number, home_ip, dest_ip);
    udp_header_t udph = create_udp_header(home_port, dest_port, data_read_number);

    init_packet_headers(preparing_packet, &eth, &iph, &udph);

    return ret_val;
}

#ifdef _WIN32
DWORD WINAPI thread_function_sending(void* sending_device) {
#else
void* thread_function_sending(void* sending_device) {
#endif
    printf("Packet sending started.\n");
    unsigned int counter = 0;
    unsigned char this_thread_number = sending_thread_number++;
    unsigned char sending_fail_attempt = 0;
    while(1) {
#ifdef _WIN32
        Sleep(sending_sleep_time[this_thread_number]/1000);
        EnterCriticalSection(&sending_mutex); //Zakljucavamo zato sto ne zelimo da istovremeno i wifi i ethernet pristupe sending_packets nizu
        if(packet_sent_confirmation[packets_sent_number] < 2) { //proveravamo da li je poslat i da li je primljen ACK (AKO JESTE ONDA JE 2)
            printf("Initiating a packet sending for packet %d by thread %d.\n", packets_sent_number, this_thread_number);
            if(pcap_sendpacket((pcap_t *)sending_device,
                               (char*)&sending_packets[packets_sent_number],
                               sizeof(packet_t))) {
                printf("Sending failed by thread %d.\n", this_thread_number);
                if((sending_sleep_time[this_thread_number] *= 2) > SENDING_FAIL_ATTEMPT_CLIENT) {
                    printf("Critical number of sending failed by thread %d. Sending stoped.\n", this_thread_number);
                }
            } else {
                packet_sent_confirmation[counter] = 1;
                printf("Packet %d sent by thread %d.\n", packets_sent_number, this_thread_number);
                packets_sent_number++;
                if(packets_sent_number >= packet_number) {
                    //printf("Paket number %d\n", packet_number);
                    sending_sleep_time[this_thread_number] = SENDING_FAIL_ATTEMPT_CLIENT*10; //stavljamo sleep time na sleep funkciju na 1s
                    packets_sent_number = 0;
                } else {
                    sending_sleep_time[this_thread_number] = MINIMUM_TIMEOUT_TIME;
                }
            }
        }
        LeaveCriticalSection(&sending_mutex);
#else
        usleep(sending_sleep_time[this_thread_number]);
        pthread_mutex_lock(&sending_mutex); //Zakljucavamo zato sto ne zelimo da istovremeno i wifi i ethernet pristupe sending_packets nizu
        if(packet_sent_confirmation[packets_sent_number] < 2) { //proveravamo da li je poslat i da li je primljen ACK (AKO JESTE ONDA JE 2)
            printf("Initiating a packet sending for packet %d by thread %d.\n", packets_sent_number, this_thread_number);
            if(pcap_sendpacket((pcap_t *)sending_device,
                               (char*)&sending_packets[packets_sent_number],
                               sizeof(packet_t))) {
                printf("Sending failed by thread %d.\n", this_thread_number);
                if((sending_sleep_time[this_thread_number] *= 2) > SENDING_FAIL_ATTEMPT_CLIENT) {
                    printf("Critical number of sending failed by thread %d. Sending stoped.\n", this_thread_number);
                }
            } else {
                packet_sent_confirmation[counter] = 1;
                printf("Packet %d sent by thread %d.\n", packets_sent_number, this_thread_number);
                packets_sent_number++;
                if(packets_sent_number >= packet_number) {
                    //printf("Paket number %d\n", packet_number);
                    sending_sleep_time[this_thread_number] = SENDING_FAIL_ATTEMPT_CLIENT*10; //stavljamo sleep time na sleep funkciju na 1s
                    packets_sent_number = 0;
                } else {
                    sending_sleep_time[this_thread_number] = MINIMUM_TIMEOUT_TIME;
                }
            }
        }


        pthread_mutex_unlock(&sending_mutex);
    //Zakljucavamo zato sto ne zelimo da istovremeno i wifi i ethernet pristupe sending_packets nizu
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

    struct bpf_program fcode;

    FILE * data_file;

    packet_t sending_packet; //PACKET_ARRAY
    char errorMsg[PCAP_ERRBUF_SIZE + 1];

    unsigned int netmask_wifi, netmask_ethernet;
    char filter[] = "udp and dst port 6000";
    unsigned char i, j, k; //iterators

    memset(sending_packets, 0, PACKET_ARRAY_MAX_LEN*sizeof(packet_t));

    // Retrieve the device list
    if(pcap_findalldevs(&devices, errorMsg) == -1)
    {
        printf("Error in pcap_findalldevs: %s\n", errorMsg);
        return -1;
    }

    //OVO MORA DA STOJI ZATO STO NAM TREBAJU DVA UREDJAJA ZA SLANJE
    //JEDAN ZA WIFI DRUGI ZA ETHERNET

    printf("Choose an ETHERNET device:\n");
    ethernet_device_item = select_device(devices);
    printf("Choose a WiFi device:\n");
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
        printf("\nChoose a valid ETHERNET based device.\n");
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
    //printf("A");
    //Checking if WiFi device was choosen
    /*if(pcap_datalink(wifi_device) != DLT_IEEE802_11) 	{
        printf("\nChoose a valid WiFi based device.\n");
        pcap_freealldevs(devices);
        return -1;
    }*/
    //Open file for reading
    if((data_file = fopen("input.txt", "r")) == NULL) {
        printf("Could not open file 'random.txt'\n");
        return -1;
    }
    printf("Starting packet preparation sequence.\n");
    while(prepare_packet_for_sending(data_file, &sending_packet) >= 0) { //ova funkcija vraca -1 kada je stigla do end of file
        sending_packet.packet_number = packet_number;
        sending_packets[packet_number] = sending_packet;
        //printf("Trying to calculate sum. \n");
        sending_packets[packet_number].udph.checksum = htons(calc_udp_checksum(&sending_packet)); //Ovde racunamo checksum
        //printf("Packet number %d loaded.\n", packet_number);
        packet_number++;
    }
    for(i = 0; i < packet_number; i++) {
        sending_packets[packet_number].expected_packet_num = packet_number; //Moze se optimizovati da samo prvi paket salje packet_number
    }
    printf("Packet preparation finished. Number of packets prepared: %d\n", packet_number);

    /* SETOVANJE FILTERA BEGIN */

#ifdef _WIN32
    if(ethernet_device_item->addresses != NULL)
        /* Retrieve the mask of the first address of the interface */
        netmask_ethernet = ((struct sockaddr_in *)(ethernet_device_item->addresses->netmask))->sin_addr.S_un.S_addr;
    else
        /* If the interface is without addresses we suppose to be in a C class network */
        netmask_ethernet = 0xffffff;
#else
    if (!ethernet_device_item->addresses->netmask)
        netmask_ethernet = 0;
    else
        netmask_ethernet = ((struct sockaddr_in *)(ethernet_device_item->addresses->netmask))->sin_addr.s_addr;
#endif

    /* SETOVANJE FILTERA END */


    if (pcap_compile(ethernet_device, &fcode, filter, 1, netmask_ethernet) < 0)
    {
         pcap_freealldevs(devices);
         printf("\n Unable to compile the packet filter. Check the syntax.\n");
         return -1;
    }

    // Set the filter
    if (pcap_setfilter(ethernet_device, &fcode) < 0)
    {
        printf("\n Error setting the filter.\n");
        return -1;
    }

#ifdef _WIN32
    if(wifi_device_item->addresses != NULL)
        /* Retrieve the mask of the first address of the interface */
        netmask_wifi = ((struct sockaddr_in *)(wifi_device_item->addresses->netmask))->sin_addr.S_un.S_addr;
    else
        /* If the interface is without addresses we suppose to be in a C class network */
        netmask_wifi = 0xffffff;
#else
    if (!wifi_device_item->addresses->netmask)
        netmask_wifi = 0;
    else
        netmask_wifi = ((struct sockaddr_in *)(wifi_device_item->addresses->netmask))->sin_addr.s_addr;
#endif


    if (pcap_compile(wifi_device, &fcode, filter, 1, netmask_wifi) < 0)
    {
         pcap_freealldevs(devices);
         printf("\n Unable to compile the packet filter. Check the syntax.\n");
         return -1;
    }

    // Set the filter
    if (pcap_setfilter(wifi_device, &fcode) < 0)
    {
        printf("\n Error setting the filter.\n");
        return -1;
    }

    /* SETOVANJE FILTERA END */

#ifdef _WIN32
    InitializeCriticalSection(&sending_mutex);
    HANDLE sending_thread[2], receiving_thread[2];
    sending_thread[0] = CreateThread(NULL, 0, thread_function_sending, ethernet_device, NULL, 0, NULL);
    sending_thread[1] = CreateThread(NULL, 0, thread_function_sending, wifi_device, NULL, 0, NULL);
    receiving_thread[0] = CreateThread(NULL, 0, thread_function_receive, ethernet_device, NULL, 0, NULL);
    receiving_thread[1] = CreateThread(NULL, 0, thread_function_receive, wifi_device, NULL, 0, NULL);
    CloseThread(sending_thread[0]);
    CloseThread(sending_thread[1]);
    CloseThread(receiving_thread[0]);
    CloseThread(receiving_thread[1]);
#else

    pthread_mutex_init(&sending_mutex, NULL);
    pthread_t sending_thread[2], receiving_thread[2]; //One sending thread is for WiFi, other is for internet
                                             //One receiving thread is for WiFi, other is for internet
    pthread_create(&sending_thread[0], NULL, thread_function_sending, wifi_device);
    pthread_create(&sending_thread[1], NULL, thread_function_sending, ethernet_device);
    pthread_create(&receiving_thread[0], NULL, thread_function_receive, wifi_device);
    pthread_create(&receiving_thread[1], NULL, thread_function_receive, ethernet_device);
    pthread_detach(sending_thread[0]);
    pthread_detach(sending_thread[1]);
    pthread_detach(receiving_thread[0]);
    pthread_detach(receiving_thread[1]); //KADA SE DETACHUJE ONDA DOBIJEMO SEG FAULT

#endif
    while(1) {
        usleep(100000000);
    }
    return 0;
}
