#include <stdio.h>
#include <pcap.h>

int main(int argc, char *argv[])
{

    // All of this lines find the  device for sniffing
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

    //Opening the device for sniffing
    pcap_t *handle;
    handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
        return 2;
    }

    // Closing all
    pcap_freealldevs(alldevs);
    pcap_close(handle);
    return 0;
}