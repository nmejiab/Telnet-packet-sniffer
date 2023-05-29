#include <stdio.h>
#include <pcap.h>

int main(int argc, char *argv[])
{
    char *dev;
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_if_t *alldevs;
    pcap_if_t *d;

    if (pcap_findalldevs(&alldevs, errbuf) == -1) {
        fprintf(stderr, "Error finding devices: %s\n", errbuf);
        return 2;
    }

    dev = alldevs->name;
    printf("Device: %s\n", dev);

    pcap_freealldevs(alldevs);
    return 0;
}