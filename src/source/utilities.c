#include <stdio.h>
#include "../header/utilities.h"
#include <stdlib.h>
#include <string.h>

#ifdef _MSC_VER
#else
    /* LINUX COMPATIBILITY BEGIN */
    #include <netinet/in.h>
    /* LINUX COMPATIBILITY END */
#endif

//void print_interface(pcap_if_t *dev)
//{
//    pcap_addr_t *addr;

//    printf("\n\t ---------------------- Network interface ---------------------------- \n\n");

//    // Name
//    printf("\t Name: \t\t %s\n",dev->name);

//    // Description
//    char* convert_sockaddr_to_string(struct sockaddr* address)
//    {
//        return (char *) inet_ntoa(((struct sockaddr_in *) address)->sin_addr);
//    }
//    if (dev->description)
//        printf("\t Description: \t %s\n",dev->description);

//    // Loopback Address
//    printf("\t Loopback: \t %s\n",(dev->flags & PCAP_IF_LOOPBACK)?"yes":"no");

//    // IP addresses
//    for(addr = dev->addresses; addr; addr = addr->next)
//    {
//        printf("\n\t ADDRESS\n");

//        switch(addr->addr->sa_family)
//        {
//            case AF_INET:
//                printf("\t - Address Type: \t IPv4\n");
//                break;

//            default:
//                printf("\t - Address Type: \t Other\n");
//                break;
//        }
//    }
//}
#ifdef _WIN32
    /* WINDOWS COMPATIBILITY BEGIN */
    /* WINDOWS COMPATIBILITY END */
#else
    /* LINUX COMPATIBILITY BEGIN */
    char* convert_sockaddr_to_string(struct sockaddr* address)
    {
        return (char *) inet_ntoa(((struct sockaddr_in *) address)->sin_addr);
    }
    /* LINUX COMPATIBILITY END */
#endif


pcap_if_t* select_device(pcap_if_t* devices)
{
    int device_number;
    int i = 0;			// Count devices and provide jumping to the selected device

    pcap_if_t* device;	// Iterator for device lis
    // Print the list
    for(device=devices; device; device=device->next)
    {
        printf("%d. %s", ++i, device->name);
        if (device->description)
            printf(" (%s)\n", device->description);
        else
            printf(" (No description available)\n");
    }

    // Check if list is empty
    if(i==0)
    {
        printf("\nNo interfaces found! Make sure libpcap/WinPcap is installed.\n");
        return NULL;
    }

    // Pick one device from the list
    printf("Enter the interface number (1-%d):", i);
    scanf("%d", &device_number);

    if(device_number < 1 || device_number > i)
    {
        printf("\nInterface number out of range.\n");
        return NULL;
    }

    // Jump to the selected device
    printf("SD: A\n");
    for (device=devices, i=0; i< device_number-1; device=device->next, i++);
    printf("SD: B\n");
    return device;
}

void print_ethernet_header(ethernet_header_t * eth)
{
    printf("\n=============================================================");
    printf("\n\tDATA LINK LAYER  -  Ethernet");

    printf("\n\tDestination address:\t%.2x:%.2x:%.2x:%.2x:%.2x:%.2x", eth->dest_address[0], eth->dest_address[1], eth->dest_address[2], eth->dest_address[3], eth->dest_address[4], eth->dest_address[5]);
    printf("\n\tSource address:\t\t%.2x:%.2x:%.2x:%.2x:%.2x:%.2x", eth->src_address[0], eth->src_address[1], eth->src_address[2], eth->src_address[3], eth->src_address[4], eth->src_address[5]);
    printf("\n\tNext protocol:\t\t0x%.4x", ntohs(eth->type));

    printf("\n=============================================================");

    return;
}

// Print content of ip header
void print_ip_header(ip_header_t * iph)
{
    printf("\n=============================================================");
    printf("\n\tNETWORK LAYER  -  Internet Protocol (IP)");

    printf("\n\tVersion:\t\t%u", iph->version);
    printf("\n\tHeader Length:\t\t%u", iph->header_length*4);
    printf("\n\tType of Service:\t%u", iph->tos);
    printf("\n\tTotal length:\t\t%u", ntohs(iph->length));
    printf("\n\tIdentification:\t\t%u", ntohs(iph->identification));
    printf("\n\tFlags:\t\t\t%u", ntohs(iph->fragmentation) & 0b111);
    printf("\n\tFragment offset:\t%u", ntohs(iph->fragmentation) >> 3);
    printf("\n\tTime-To-Live:\t\t%u", iph->ttl);
    printf("\n\tNext protocol:\t\t%u", iph->next_protocol);
    printf("\n\tHeader checkSum:\t%u", ntohs(iph->checksum));
    printf("\n\tSource:\t\t\t%u.%u.%u.%u", iph->src_addr[0], iph->src_addr[1], iph->src_addr[2], iph->src_addr[3]);
    printf("\n\tDestination:\t\t%u.%u.%u.%u", iph->dst_addr[0], iph->dst_addr[1], iph->dst_addr[2], iph->dst_addr[3]);

    printf("\n=============================================================");

    return;
}

int packet_circular_buffer_init(packet_circular_buffer_t * buffer) {
    if(buffer == NULL) {
        return -1;
    }
    memset(buffer, 0, CIRCULAR_BUFFER_SIZE*sizeof(packet_circular_buffer_t));
    return 0;
}

int packet_circular_buffer_pop(packet_circular_buffer_t * buffer, packet_t * poped_packet) {
    if(buffer->current_number_of_elements <= 0) {
        return -1;
    }
    buffer->read_buffer_index = (buffer->read_buffer_index + 1)%CIRCULAR_BUFFER_SIZE;
    buffer->current_number_of_elements--;
    *poped_packet = (buffer->packet_buffer)[buffer->read_buffer_index];
    return 0;
}

int packet_circular_buffer_push(packet_circular_buffer_t * buffer, packet_t * packet) {
    if(packet == NULL) {
        return -1;
    } if (buffer->current_number_of_elements > CIRCULAR_BUFFER_SIZE) {
        return -2;
    }
    buffer->write_buffer_index = (buffer->write_buffer_index + 1)%CIRCULAR_BUFFER_SIZE;
    buffer->current_number_of_elements++;
    (buffer->packet_buffer)[buffer->write_buffer_index] = *packet;
    return 0;
}

int packet_circular_buffer_read_at(packet_circular_buffer_t * buffer, packet_t * read_packet, short index) {
    if(index < CIRCULAR_BUFFER_SIZE) {
        return -1;
    }
    *read_packet = buffer->packet_buffer[index];
    return 0;
}

// Print raw application data
void print_application_data(unsigned char *data, long data_length)
{
    printf("\n=============================================================");
    printf("\n\tAPPLICATION DATA");

    int i;
    printf("\n-------------------------------------------------------------\n\t");
    for(i = 0; i < data_length; i = i + 1)
    {
        printf("%.2x ", ((unsigned char*)data)[i]);

        // 16 bytes per line
        if ((i+1) % 16 == 0)
            printf("\n\t");
    }
    printf("\n-------------------------------------------------------------");

    printf("\n=============================================================");
}

void print_udp_header(udp_header_t * uh)
{
	printf("\n=============================================================");
    printf("\n\tTRANSPORT LAYER  -  User Datagram Protocol (UDP)");

    printf("\n\tSource port:\t%u", ntohs(uh->src_port));
    printf("\n\tDestination port:\t%u", ntohs(uh->dest_port));
    printf("\n\tDatagram length:\t%u", ntohs(uh->datagram_length));
    printf("\n\tChecksum:\t%u", ntohs(uh->checksum));

    printf("\n=============================================================");
}

udp_header_t create_udp_header(const unsigned short src_port,
                             const unsigned short dst_port,
                             const unsigned short data_size) {
    udp_header_t uh;

    uh.src_port = htons(src_port);
    uh.dest_port = htons(dst_port);
    uh.datagram_length = htons(sizeof(udp_header_t) +
                               data_size);

    return uh;
}

ip_header_t create_ip_header(size_t data_size,
                           const unsigned char src_addr[4],
                           const unsigned char dst_addr[4]) {
    ip_header_t ih;

    ih.header_length = IP_HEADER_LENGTH;   // optional part is removed
    ih.version = IP_VERSION;         // IPv4
    ih.tos = IP_TYPE_OF_SERVICE;             // all set to default
    ih.length = htons(sizeof(ip_header_t) +
                      sizeof(udp_header_t) +
                      data_size);
    ih.identification = 0; // za pracenje fregmentacije, ne koristi se
    ih.fragmentation = htons(IP_FRAGMENTATION_FLAG);
    //ih.fragm_offset = htons(FRAGMLESS);   // fragmentation is forbidden
    ih.ttl = htons(IP_TTL);
    ih.next_protocol = IP_NEXT_PROTOCOL;
    memcpy(ih.src_addr, src_addr, 4);
    memcpy(ih.dst_addr, dst_addr, 4);

    ih.checksum = htons(calc_ip_checksum(&ih));

    return ih;
}

unsigned short calc_ip_checksum(const ip_header_t *ih) {
    int i;
    unsigned int sum = 0;
    unsigned short *buff = (unsigned short*)ih;

    for (i = 0; i < 10; i++) {

        sum += buff[i];
        if(sum >> 16)//ako imamo carry pit onda ga dodajemo napred
            sum = (sum & 0xffff) + 1;
    }

    return (unsigned short)(~sum);
}

unsigned short calc_udp_checksum(const packet_t * p) { //obrati paznju da se ovo zove tek kada se podaci napune u udp paket
    unsigned long int checksum_value = 0;
    unsigned char i;
    unsigned short *buff = (unsigned short*)p;
    for(i = 0; i < sizeof(packet_t)/2; i++) { //sizeof vraca broj byte-a, /2 ce vracati broj short-ova (16)-bitnih vrednosti
        if(i = 3) continue; //preskacemo samo checksum polje, koje je na cetvrtom mestu
        checksum_value += buff[i];// idemo kroz citav paket
        if(checksum_value >> 16)//ako imamo carry pit onda ga dodajemo napred
            checksum_value = (checksum_value & 0xffff) + 1;
    }

                                               //ovako kazu na netu
    return (unsigned short)(~checksum_value); //Na netu kaze da se suma komplementira
}

ethernet_header_t create_eth_header(const unsigned char src_addr[6],
                                  const unsigned char dst_addr[6]) {
    ethernet_header_t eh;

    memcpy(eh.src_address, src_addr, 6);
    memcpy(eh.dest_address, dst_addr, 6);
    eh.type = htons(ETHERNET_TYPE);

    return eh;
}

void init_packet_headers(packet_t * p, const ethernet_header_t * eh,
                     const ip_header_t * ih,
                     const udp_header_t * uh) {

    p->eth = *eh;
    p->iph = *ih;
    p->udph = *uh;
}
