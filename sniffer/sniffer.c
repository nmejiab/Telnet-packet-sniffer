#include <stdio.h>
#include <pcap.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <arpa/inet.h>

void process_packet(const unsigned char *packet, int packet_length)
{
    struct ip *ip_header;
    struct icmphdr *icmp_header;

    ip_header = (struct ip *)(packet + 14); // Offset of 14 for Ethernet header
    icmp_header = (struct icmphdr *)(packet + 14 + (ip_header->ip_hl * 4)); // Offset of 14 + size of IP header

    char src_ip[INET_ADDRSTRLEN];
    char dst_ip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &(ip_header->ip_src), src_ip, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, &(ip_header->ip_dst), dst_ip, INET_ADDRSTRLEN);

    printf("Source IP: %s\n", src_ip);
    printf("Destination IP: %s\n", dst_ip);

    printf("Packet: ");
    for (int i = 0; i < packet_length; i++) {
        printf("%02X ", packet[i]);
    }

    printf("\n\n");
}

int main(int argc, char *argv[])
{

    // All of this lines find the  device for sniffing
    char *dev;
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_if_t *alldevs;

    if (pcap_findalldevs(&alldevs, errbuf) == -1) {
        fprintf(stderr, "Error finding devices: %s\n", errbuf);
        return 2;
    }

    dev = alldevs->name;
    printf("Device: %s\n", dev);

    //Opening the device for sniffing
    pcap_t *handle;
    handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
        return 2;
    }
    // Compile the telnet filter
    struct pcap_pkthdr header;
    const unsigned char *packet;
    char filter_exp[] = "tcp port 23";
    struct bpf_program fp;

    if (pcap_compile(handle, &fp, filter_exp, 0, PCAP_NETMASK_UNKNOWN) == -1) {
        fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
        return 2;
    }

    // Install the telnet filter
    if (pcap_setfilter(handle, &fp) == -1) {
        fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle));
        return 2;
    }

    // Printing the body of the packets
    int packet_count = 0;
    while (1) {
        int result = pcap_next_ex(handle, (struct pcap_pkthdr **)&header, &packet);
        if (result == 1) {
            printf("Packet captured #%d\n", ++packet_count);
            process_packet(packet, header.caplen);
        } else if (result == -1) {
            fprintf(stderr, "Error reading packet: %s\n", pcap_geterr(handle));
            break;
        } else if (result == 0) {
            // No more packets to capture in this iteration
            continue;
        }
    }

    // Closing all
    pcap_close(handle);
    pcap_freealldevs(alldevs);
    return 0;
}