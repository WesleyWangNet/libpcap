#include <stdio.h>
#include <pcap/pcap.h>
#include <string.h>
#include <stdlib.h>
#include <netinet/ether.h>


static void callback(unsigned char *user_buf, const struct pcap_pkthdr *pkthdr, \
              const unsigned char *recv_buf)
{
    struct ether_header *eth_hdr = (struct ether_header *)recv_buf;
    printf("%s %d, caplen: %d\r\n", __FUNCTION__, __LINE__,  pkthdr->caplen);
    printf("dst:%02x:%02x:%02x:%02x:%02x:%02x\n", eth_hdr->ether_shost[0], eth_hdr->ether_\
shost[1], eth_hdr->ether_shost[2], eth_hdr->ether_shost[3], eth_hdr->ether_shost[4], eth_h\
dr->ether_shost[5]);
    printf("dst:%02x:%02x:%02x:%02x:%02x:%02x\n", eth_hdr->ether_dhost[0], eth_hdr->ether_\
dhost[1], eth_hdr->ether_dhost[2], eth_hdr->ether_dhost[3], eth_hdr->ether_dhost[4], eth_h\
dr->ether_dhost[5]);

}

int main(void)
{
    char *dev = NULL;
    char err_buf[128] = {0};

    pcap_if_t *all_devs;
    if (pcap_findalldevs(&all_devs, err_buf) == -1) {
        fprintf(stderr, "error finding devices");
        return 1;
    }

    if (all_devs == NULL) {
        fprintf(stderr, "no devices found");
        return 1;
    }

    char *dev_name = all_devs->name;
    printf("dev: %s\n", dev_name);

    pcap_t *pcap_head = pcap_open_live(dev_name, 1500, 1, 10, err_buf);
    if (pcap_head == NULL) {
        perror("open live failed: \r\n");
        exit(-1);
    }

    unsigned int net_ip;
    unsigned int net_mask;
    if (pcap_lookupnet(dev_name, &net_ip, &net_mask, err_buf) < 0) {
        perror("pcap_lookupnet failed: \r\n");
        exit(-1);
    }

    struct bpf_program program;
    int err_log = pcap_compile(pcap_head, &program, "udp", 2, net_mask);
    if (err_log < 0) {
        perror("pcap_compile failed: \r\n");
        exit(-1);
    }

    err_log = pcap_setfilter(pcap_head, &program);
    if (err_log < 0) {
        perror("pcap_setfilter failed: \r\n");
        exit(-1);
    }

    err_log = pcap_loop(pcap_head, 1, callback, NULL);
    if(err_log < 0) {
        perror("pcap_loop failed: \r\n");
        exit(-1);
    }

    return 0;
}
