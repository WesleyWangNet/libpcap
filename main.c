#include <stdio.h>
#include <pcap/pcap.h>
#include <string.h>
#include <stdlib.h>



int main(int argc, char const *argv[])
{
    char *dev = NULL;
    char err_buf[128] = {0};
    //查找设备dev
    #if 0
    //pcap_lookupde is deprecated
    
    dev = pcap_lookupdev(err_buf);
    if (dev == NULL) {
        perror("can't find device: \r\n");
        exit(-1);
    }
    #endif
    pcap_if_t *all_devs;
    if(pcap_findalldevs(&all_devs, err_buf) == -1){
        fprintf(stderr, "error finding devices");
        return 1;
    }

    if (all_devs == NULL) {
        fprintf(stderr, "no devices found");
        return 1;
    }
    dev = all_devs->name;

    //ubuntu 默认ens33
    printf("dev: %s\n", dev);

    //打开设备
    pcap_t * pcap_head = pcap_open_live(dev, 1500, 1, 10, err_buf);
    if (pcap_head == NULL) {
        perror("open live failed: \r\n");
        exit(-1);
    }

    //捕获一个数据包
    struct pcap_pkthdr pkthdr;
    unsigned char *recv_buf = NULL;
    recv_buf = pcap_next(pcap_head, &pkthdr);
    if (recv_buf == NULL) {
        perror("pcap_next failed: \r\n");
        exit(-1);
    }

    printf("dst:%02x:%02x:%02x:%02x:%02x:%02x\n", recv_buf[0], recv_buf[1], recv_buf[2], recv_buf[3], recv_buf[4], recv_buf[5]);
    printf("src:%02x:%02x:%02x:%02x:%02x:%02x\n", recv_buf[6], recv_buf[7], recv_buf[8], recv_buf[9], recv_buf[10], recv_buf[11]);



    return 0;
}