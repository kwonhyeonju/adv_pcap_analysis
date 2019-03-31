#pragma once

void usage(){
    printf("syntax: pcap_test <interface>\n");
    printf("sample: pcap_test wlan0\n");
}

struct eth_h{
    u_int8_t ether_dhost[ETH_ALEN]; /* size : 6	*/
    u_int8_t ether_shost[ETH_ALEN];	/* size : 6	*/
    uint16_t ether_type;            /* size : 2	*/
};
struct ip_h{
    unsigned int ihl:4;
    unsigned int version:4;
    uint8_t tos;
    uint16_t tot_len;
    uint16_t id;
    uint16_t frag_off;
    uint8_t ttl;
    uint8_t protocol;
    uint16_t check;
    uint8_t saddr[4];
    uint8_t daddr[4];
};
struct tcp_h{

    unsigned short sport;
    unsigned short dport;
    unsigned int seq;
    unsigned int acknow;
    unsigned char ns:1;
    unsigned char res:3;
    unsigned char Hlen:4;
    unsigned char fin:1;
    unsigned char syn:1;
    unsigned char rst:1;
    unsigned char psh:1;
    unsigned char ack:1;
    unsigned char urg:1;
    unsigned char ecn:1;
    unsigned char cwr:1;
    unsigned short win;
    unsigned short chsum;
    unsigned short urp;

};

static struct ip_h *ih;
static struct tcp_h *th;
static struct eth_h *eh;

