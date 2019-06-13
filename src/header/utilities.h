#ifndef UTILITIES_H
#define UTILITIES_H
#include <pcap.h>

#define PACKET_DATA_LEN 255
#define SENDING_FAIL_ATTEMPT_CLIENT 5
#define SENDING_PAUSE 3000000 //3 s
#define RECEIVE_PAUSE 3000000 //3 s
#define RECEIVE_FAIL_ATTEMPT_CLIENT 5
#define CIRCULAR_BUFFER_SIZE 100
#define MAXIUM_TIMEOUT_TIME 500 //500 ms
#define MINIMUM_TIMEOUT_TIME 20 //20 ms
#define IP_VERSION 4
#define IP_TYPE_OF_SERVICE 0 //DEFAULT
#define IP_HEADER_LENGTH 5
#define IP_FRAGMENTATION_FLAG 1 //ZABRANJENO
#define IP_TIME_TO_LIVE 13
#define IP_NEXT_PROTOCOL 17
#define ETHERNET_TYPE 0x0800 //za IPv4


typedef struct ethernet_header{
    unsigned char dest_address[6];		// Destination address
    unsigned char src_address[6];		// Source address
    unsigned short type;				// Type of the next layer
}ethernet_header_t;

// IPv4 header
typedef struct ip_header{
    unsigned char version :4;		// Version (4 bits)
    unsigned char header_length :4;	// Internet header length (4 bits)
    unsigned char tos;				// Type of service
    unsigned short length;			// Total length
    unsigned short identification;	// Identification for fragmentation
    //unsigned short fragm_flags :3;  // Flags (3 bits) & Fragment offset (13 bits)
    //unsigned short fragm_offset :13;// Flags (3 bits) & Fragment offset (13 bits)
    unsigned short fragmentation;
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
    ethernet_header_t eth;
    ip_header_t iph;
    udp_header_t udph;
    unsigned short expected_packet_num; //Number of expected packets
    int packet_number;
    unsigned char data[PACKET_DATA_LEN]; //Actual datpa
}packet_t;

typedef struct packet_circular_buffer {
    short read_buffer_index, write_buffer_index;
    short current_number_of_elements;
    packet_t packet_buffer[CIRCULAR_BUFFER_SIZE];
} packet_circular_buffer_t;

/*typedef struct sending_params{ //Struktura za thread za slanje
    pcap_t * sending_device;
    unsigned int number_of_packets;
} sending_params_t;
*/
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


/**
 * @brief print_application_data
 * @param data
 * @param data_length
 */
void print_application_data(unsigned char* data, long data_length);

/**
 * @brief print_udp_header
 * @param udh
 */
void print_udp_header(udp_header_t * uh);

/**
 * @brief packet_circular_buffer_init: Initializes the packet_circular_buffer
 * @param buffer
 * @return
 */
int packet_circular_buffer_init(packet_circular_buffer_t * buffer);

/**
 * @brief packet_circular_buffer_pop: Removes one element from packet_circular_buffer at read_buffer_index
 * @param buffer
 * @param poped_packet
 * @return
 */
int packet_circular_buffer_pop(packet_circular_buffer_t * buffer, packet_t * poped_packet);

/**
 * @brief packet_circular_buffer_push: Adds one element to packet_circular_buffer at write_buffer_index
 * @param buffer
 * @param packet
 * @return
 */
int packet_circular_buffer_push(packet_circular_buffer_t * buffer, packet_t * packet);

/**
 * @brief packet_circular_buffer_read_at: Reads an element at "index" without removing it from the buffer
 * @param buffer
 * @parama read_packet
 * @param index: Which element we want to read
 * @return
 */
int packet_circular_buffer_read_at(packet_circular_buffer_t * buffer, packet_t * read_packet, short index);

ethernet_header_t create_eth_header(const unsigned char src_addr[6],
                                  const unsigned char dst_addr[6]);

ip_header_t create_ip_header(size_t data_size,
                           const unsigned char src_addr[4],
                           const unsigned char dst_addr[4]);

udp_header_t create_udp_header(const unsigned short src_port,
                             const unsigned short dst_port,
                             const unsigned short data_size);

void init_packet_headers(packet_t * p, const ethernet_header_t * eh,
                     const ip_header_t * ih,
                     const udp_header_t * uh);

unsigned short calc_ip_checksum(const ip_header_t *ih);

unsigned short calc_udp_checksum(const packet_t * p);

#endif // UTILITIES_H


