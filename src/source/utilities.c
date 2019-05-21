#include <stdio.h>
#include "../header/utilities.h"

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
    int i=0;			// Count devices and provide jumping to the selected device
    pcap_if_t* device;	// Iterator for device list

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
    for(device=devices, i=0; i< device_number-1 ;device=device->next, i++);

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
    printf("\n\tFlags:\t\t\t%u", ntohs(iph->fragm_flags));
    printf("\n\tFragment offset:\t%u", ntohs(iph->fragm_offset));
    printf("\n\tTime-To-Live:\t\t%u", iph->ttl);
    printf("\n\tNext protocol:\t\t%u", iph->next_protocol);
    printf("\n\tHeader checkSum:\t%u", ntohs(iph->checksum));
    printf("\n\tSource:\t\t\t%u.%u.%u.%u", iph->src_addr[0], iph->src_addr[1], iph->src_addr[2], iph->src_addr[3]);
    printf("\n\tDestination:\t\t%u.%u.%u.%u", iph->dst_addr[0], iph->dst_addr[1], iph->dst_addr[2], iph->dst_addr[3]);

    printf("\n=============================================================");

    return;
}
