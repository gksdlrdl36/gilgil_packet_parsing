#include <pcap.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>

void usage() {
  printf("syntax: pcap_test <interface>\n");
  printf("sample: pcap_test wlan0\n");
}

typedef struct packet_infor{
    const u_char DesMac[6];
    const u_char SouMac[6];
    const u_char Check_IP[2];
    const u_char tmp1[9];
    const u_char Check_TCP[1];
    const u_char tmp2[2];
    const u_char DesIP[4];
    const u_char SouIP[4];
    const u_char SouPort[2];
    const u_char DesPort[2];
    const u_char tmp3[16];
    const u_char Tcp_data[10]={0,};
}p1;

void print_mac(const u_char *a){
    printf("Mac is - %02x:%02x:%02x:%02x:%02x:%02x\n",a[0],a[1],a[2],a[3],a[4],a[5]);
}

void print_ip(const u_char *p){
    printf("IP is - %d.%d.%d.%d\n",p[0],p[1],p[2],p[3]);
}



void gilgilishandsome(struct packet_infor *p, const u_char* a)
{
                printf("===========================gilgil is so cool!================================\n");
                printf("Destination ");
                print_mac(&a[0]);
                printf("Source ");
                print_mac(&a[6]);

                printf("Destination ");
                print_ip(&a[26]);
                printf("Source ");
                print_ip(&a[30]);

                printf("Destination Port is - %d\n",(p->DesPort[0] << 8 | p->DesPort[1]));
                printf("Source Port is - %d\n",(p->SouPort[0] << 8 | p->SouPort[1]));

                printf("Data is - %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x",p->Tcp_data[0],p->Tcp_data[1],p->Tcp_data[2],p->Tcp_data[3],p->Tcp_data[4],p->Tcp_data[5],
                                                                                     p->Tcp_data[6],p->Tcp_data[7],p->Tcp_data[8],p->Tcp_data[9]);
                printf("=============================================================================\n");
}

int main(int argc, char* argv[]) {
  if (argc != 2) {
    usage();
    return -1;
  }

  char* dev = argv[1];
  char errbuf[PCAP_ERRBUF_SIZE];
  pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
  if (handle == NULL) {
    fprintf(stderr, "couldn't open device %s: %s\n", dev, errbuf);
    return -1;
  }

  while (true) {
    struct pcap_pkthdr* header;
    const u_char* packet;
    int res = pcap_next_ex(handle, &header, &packet);

    if (res == 0) continue;

    if (res == -1 || res == -2) break;




    p1 *a = (struct packet_infor*)packet;

    if(       a->Check_IP[0]==8
              &&a->Check_IP[1]==0
              &&a->Check_TCP[0]==6)
    {
               if((a->DesPort[0] << 8 | a->DesPort[1])==80
                ||(a->DesPort[0] << 8 | a->DesPort[1])==443
                ||(a->SouPort[0] << 8 | a->SouPort[1])==80
                ||(a->SouPort[0] << 8 | a->SouPort[1])==443
                    )
               {
                    printf("%u bytes captured\n", header->caplen);
                    gilgilishandsome(a, packet);
                }
    }

  }

  pcap_close(handle);
  return 0;
}


