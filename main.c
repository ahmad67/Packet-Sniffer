#include <pcap.h>
#include <stdio.h>

void packet_handler(u_char *user_data, const struct pcap_pkthdr *pkthdr, const u_char *packet) {
    printf("Packet captured: %d bytes\n", pkthdr->len);
}

int main() {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_if_t *alldevs, *device;

    // Get the list of available devices
    if (pcap_findalldevs(&alldevs, errbuf) == -1) {
        fprintf(stderr, "Error finding devices: %s\n", errbuf);
        return 1;
    }

    // Use the first available device
    device = alldevs;
    pcap_t *handle = pcap_open_live(device->name, BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Error opening device: %s\n", errbuf);
        return 2;
    }

    // Capture packets
    pcap_loop(handle, 10, packet_handler, NULL);

    // Clean up
    pcap_freealldevs(alldevs);
    pcap_close(handle);
    return 0;
}
