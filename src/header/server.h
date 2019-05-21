#ifndef SERVER_H
#define SERVER_H
#include <pcap.h>
#include "utilities.h"
//OVE DVE FUNKCIJE PROSLEDJUJES NITIMA
int server_receive_packet(pcap_if_t * device, packet_t * packet_receiving_array, int * packet_receiving_index);
int server_send_packet(pcap_if_t * device, packet_t * packet_sending_array, int * packet_sending_index);
#endif // SERVER_H
