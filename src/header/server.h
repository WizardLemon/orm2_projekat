#ifndef SERVER_H
#define SERVER_H
#include <pcap.h>
#include "utilities.h"

void packet handler(unsigned char *interface, const struct pcap_pkthdr* packet_header, const unsigned char* packet_data);
#endif // SERVER_H
