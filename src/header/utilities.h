#ifndef UTILITIES_H
#define UTILITIES_H
#include <pcap.h>
#define PACKET_DATA_LEN 255

typedef struct ethernet_header{
    unsigned char dest_address[6];		// Destination address
    unsigned char src_address[6];		// Source address
    unsigned short type;				// Type of the next layer
}ethernet_header_t;

// IPv4 header
typedef struct ip_header{
    unsigned char header_length :4;	// Internet header length (4 bits)
    unsigned char version :4;		// Version (4 bits)
    unsigned char tos;				// Type of service
    unsigned short length;			// Total length
    unsigned short identification;	// Identification
    unsigned short fragm_flags :3;  // Flags (3 bits) & Fragment offset (13 bits)
    unsigned short fragm_offset :13;// Flags (3 bits) & Fragment offset (13 bits)
    unsigned char ttl;				// Time to live
    unsigned char next_protocol;	// Protocol of the next layer
    unsigned short checksum;		// Header checksum
    unsigned char src_addr[4];		// Source address
    unsigned char dst_addr[4];		// Destination address
    unsigned int options_padding;	// Option + Padding
        // + variable part of the header
}ip_header_t;

//UDP header
typedef struct udp_header{
    unsigned short src_port;		// Source port
    unsigned short dest_port;		// Destination port
    unsigned short datagram_length;	// Length of datagram including UDP header and data
    unsigned short checksum;		// Header checksum
}udp_header_t;

typedef struct packet {
    //link_layer_header_t llh; Nisam siguran da li je potrebno
    ethernet_header_t eth;
    ip_header_t iph;
    udp_header_t udph;
    unsigned char packet_ack;
    unsigned char packet_number;
    unsigned char data[PACKET_DATA_LEN]; //Actual data
}packet_t;

/**
 * @brief print_ethernet_header
 * @param eth
 */
void print_ethernet_header(ethernet_header_t * eth);

/**
 * @brief print_ip_header
 * @param ith
 */
void print_ip_header(ip_header_t * ith);


/**
 * @brief print_interface: Prints all available networking devices
 * @param dev
 */
void print_interface(pcap_if_t *dev);

/**
 * @brief convert_sockaddr_to_string
 * @param address
 * @return
 */
char* convert_sockaddr_to_string(struct sockaddr* address);

/**
 * @brief select_device: Prints a menu that is used to select the wanted device
 * @param devices: List of devices
 * @return : Choosen device
 */
pcap_if_t* select_device(pcap_if_t* devices);

//TREBA IMPLEMENTIRATI
/**
 * @brief print_application_data
 * @param data
 * @param data_length
 */
void print_application_data(unsigned char* data, long data_length);

/**
 * @brief print_udp_header TREBA IMPLEMENTIRATI
 * @param udh
 */
void print_udp_header(udp_header_t * uh);
#endif // UTILITIES_H
