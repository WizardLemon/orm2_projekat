#ifndef CLIENT_H
#define CLIENT_H
#include <pcap.h>
#include "utilities.h"
//OVE DVE FUNKCIJE PROSLEDJUJES NITIMA
int client_receive_packet(pcap_if_t * device, packet_t * packet_receiving_array);
int client_send_packet(pcap_if_t * device, packet_t * packet_sending_array);
int reconstruct_packet_order(packet_t * buffer); //Ovo treba implementirati
#endif // CLIENT_H
