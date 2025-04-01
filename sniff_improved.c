#include <stdlib.h>
#include <stdio.h>
#include <pcap.h>
#include <arpa/inet.h>
#include <netinet/ether.h>
#include <ctype.h>

/* Ethernet header */
struct ethheader {
  unsigned char  ether_dhost[6]; /* destination host address */
  unsigned char  ether_shost[6]; /* source host address */
  unsigned short ether_type;     /* protocol type (IP, ARP, RARP, etc) */
};

/* IP Header */
struct ipheader {
  unsigned char      iph_ihl:4, //IP header length
                     iph_ver:4; //IP version
  unsigned char      iph_tos; //Type of service
  unsigned short int iph_len; //IP Packet length (data + header)
  unsigned short int iph_ident; //Identification
  unsigned short int iph_flag:3, //Fragmentation flags
                     iph_offset:13; //Flags offset
  unsigned char      iph_ttl; //Time to Live
  unsigned char      iph_protocol; //Protocol type
  unsigned short int iph_chksum; //IP datagram checksum
  struct  in_addr    iph_sourceip; //Source IP address
  struct  in_addr    iph_destip;   //Destination IP address
};

/* TCP Header */
struct tcpheader {
  unsigned short tcp_sport;               /* source port */
  unsigned short tcp_dport;               /* destination port */
  unsigned int   tcp_seq;                 /* sequence number */
  unsigned int   tcp_ack;                 /* acknowledgement number */
  unsigned char tcp_offx2;
  //unsigned char  tcp_Reserved:4;
  //unsigned char  tcp_H_len:4;               /* data offset, rsvd */
#define TH_OFF(th)      (((th)->tcp_offx2 & 0xf0) >> 4)
  unsigned char  tcp_flags;
#define TH_FIN  0x01
#define TH_SYN  0x02
#define TH_RST  0x04
#define TH_PUSH 0x08
#define TH_ACK  0x10
#define TH_URG  0x20
#define TH_ECE  0x40
#define TH_CWR  0x80
#define TH_FLAGS        (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)
  unsigned short tcp_win;                 /* window */
  unsigned short tcp_sum;                 /* checksum */
  unsigned short tcp_urp;                 /* urgent pointer */
};
/* Data */
struct data{
  unsigned char data[500];
};

void got_packet(unsigned char *args, const struct pcap_pkthdr *header,
                              const unsigned char *packet)
{
  struct ethheader *eth = (struct ethheader *)packet;
  if (ntohs(eth->ether_type) == 0x0800) { // 0x0800 is IP type
    struct ipheader * ip = (struct ipheader *)
                           (packet + sizeof(struct ethheader)); 
   struct tcpheader *tcp = (struct tcpheader *)
                            (packet + sizeof(struct ethheader)+ip->iph_ihl*4);
    struct data *data = (struct data *)(packet + sizeof(struct ethheader)+ip->iph_ihl*4+((tcp->tcp_offx2 & 0xf0)>>4)*4);
    
    //printf("size: %zu\n",sizeof(struct ethheader));
    //printf("size: %d\n",ip->iph_ihl*4);
    //printf("size: %d\n",tcp->tcp_offx2*4);
    //printf("size:%d\n",((tcp->tcp_offx2 & 0xf0)>>4)*4);

    printf("       src mac: %s\n", ether_ntoa((struct ether_addr *)eth->ether_shost));   
    printf("       dst mac: %s\n", ether_ntoa((struct ether_addr *)eth->ether_dhost));   
    printf("       src ip: %s\n", inet_ntoa(ip->iph_sourceip));   
    printf("       dst ip: %s\n", inet_ntoa(ip->iph_destip));  
    printf("       src port: %d\n", ntohs(tcp->tcp_sport));   
    printf("       dst port: %d\n", ntohs(tcp->tcp_dport));  

    printf("==========data==========\n");
    for(int i=0;i<460;i++){
      if(isprint(data->data[i]))
        printf("%c",data->data[i]);
      else{
        printf(".");
      }
    }
    printf("\n");

    /* determine protocol */
    switch(ip->iph_protocol) {                                 
        case IPPROTO_TCP:
            //printf("   Protocol: TCP\n");
            printf("========================\n");
            return;
        case IPPROTO_UDP:
            printf("   Protocol: UDP\n");
            return;
        case IPPROTO_ICMP:
            printf("   Protocol: ICMP\n");
            return;
        default:
            printf("   Protocol: others\n");
            return;
    }
  }
}

int main()
{
  pcap_t *handle;
  char errbuf[PCAP_ERRBUF_SIZE];
  struct bpf_program fp;
  char filter_exp[] = "tcp";
  bpf_u_int32 net;

  // Step 1: Open live pcap session on NIC with name enp0s3
  handle = pcap_open_live("enp0s3", BUFSIZ, 1, 1000, errbuf);

  // Step 2: Compile filter_exp into BPF psuedo-code
  pcap_compile(handle, &fp, filter_exp, 0, net);
  if (pcap_setfilter(handle, &fp) !=0) {
      pcap_perror(handle, "Error:");
      exit(EXIT_FAILURE);
  }

  // Step 3: Capture packets
  pcap_loop(handle, -1, got_packet, NULL);

  pcap_close(handle);   //Close the handle
  return 0;
}
