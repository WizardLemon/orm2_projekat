#ifndef SERVER_H
#define SERVER_H
#include <pcap.h>
#include "utilities.h"
//OVE DVE FUNKCIJE PROSLEDJUJES NITIMA
int server_receive_packet(pcap_if_t * device, packet_circular_buffer_t * buffer);
int server_send_packet(pcap_if_t * device, packet_circular_buffer_t * buffer);
#endif // SERVER_H
