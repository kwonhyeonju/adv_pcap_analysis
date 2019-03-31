#include "pcap.h"
#include <pcap.h>
#include <stdio.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/in.h>
#include <netinet/tcp.h>

int main(int argc, char* argv[]){
    if (argc != 2) {
        usage();
        return -1;
    }

    char* dev = argv[1];
    char errbuf[PCAP_ERRBUF_SIZE];

    pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if (handle == nullptr) {
        fprintf(stderr, "couldn't open device %s: %s\n", dev, errbuf);
        return -1;
    }
    while (true) {
        struct pcap_pkthdr* header;
        const u_char* packet;
        int res = pcap_next_ex(handle, &header, &packet);
        if (res == 0) continue;
        if (res == -1 || res == -2) break;

        struct eth_h *eh;
        eh = (struct eth_h *)packet;
        //printf("================ETHERNET==================\n");
        printf("smac : %02x:%02x:%02x:%02x:%02x:%02x\n",
               eh->ether_shost[0], eh->ether_shost[1], eh->ether_shost[2], eh->ether_shost[3], eh->ether_shost[4], eh->ether_shost[5]);
        printf("dmac : %02x:%02x:%02x:%02x:%02x:%02x\n\n",
               eh->ether_dhost[0], eh->ether_dhost[1], eh->ether_dhost[2], eh->ether_dhost[3], eh->ether_dhost[4], eh->ether_dhost[5]);
        //ntohs

        if(ntohs(eh->ether_type)==ETHERTYPE_IP){
            const u_char* ihs;
            ihs = packet+14;
            ih = (struct ip_h*)ihs;
            // printf("================IP==================\n");
            printf("IP Header length : %d\n",(ih->ihl)*4);
            printf("sip : %d.%d.%d.%d\n", ih->saddr[0],ih->saddr[1],ih->saddr[2],ih->saddr[3]);
            printf("dip : %d.%d.%d.%d\n\n",ih->daddr[0],ih->daddr[1],ih->daddr[2],ih->daddr[3]);
#define TCP     6
            if(ih->protocol == TCP){
                const u_char *ths;
                ths = ihs+(ih->ihl)*4;

                th = (struct tcp_h*)ths;
                //printf("================TCP==================\n");
                printf("TCP Header length : %d\n",(th->Hlen)*4);
                printf("sport : %d\n",ntohs(th->sport));
                printf("dport : %d\n\n",ntohs(th->dport));

                int i = (ih->tot_len)-(ih->ihl*4)-(th->Hlen*4);
                printf("Total data length : %d\n",i);

                if(i> 16){
                    const u_char* data;
                    data = ths+(th->Hlen)*4;
                    printf("data : ");

                    for (int i=16;i>0;i--) {
                        printf("%c",*data);
                        data++;
                    }
                    printf("\n");
                }
                else {
                    printf("Data is smaller than 16");
                }


                printf("_____________________________________\n\n");

            }
            else{printf("NO TCP\n");}
        }
        break;
    }

    pcap_close(handle);
    return 0;
}

