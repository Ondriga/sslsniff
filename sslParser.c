#include "sslParser.h"
#include <string.h>

#include <pcap.h>
#include <netinet/ip.h>

#include <pcap/pcap.h>
#include <errno.h>
#include <sys/socket.h>
#define __FAVOR_BSD          // important for tcphdr structure
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <arpa/inet.h>
#include <netinet/if_ether.h> 
#include <err.h>

#ifdef __linux__            // for Linux
#include <netinet/ether.h> 
#include <time.h>
#include <pcap/pcap.h>
#endif

#define SIZE_ETHERNET (14)       // offset of Ethernet header to L3 protocol

void tcp_handler(struct tcphdr *my_tcp){
    printf("\tSrc port = %d, dst port = %d, seq = %u",ntohs(my_tcp->th_sport), ntohs(my_tcp->th_dport), ntohl(my_tcp->th_seq));

    if (my_tcp->th_flags & TH_SYN)
        printf(", SYN");
    if (my_tcp->th_flags & TH_FIN)
        printf(", FIN");
    if (my_tcp->th_flags & TH_RST)
        printf(", RST");
    if (my_tcp->th_flags & TH_PUSH)
        printf(", PUSH");
    if (my_tcp->th_flags & TH_ACK)
        printf(", ACK");
    printf("\n");
}

void mypcap_handler(u_char *args, const struct pcap_pkthdr *header, const u_char *packet){
    struct ip *my_ip;               // pointer to the beginning of IP header
    struct ether_header *eptr;      // pointer to the beginning of Ethernet header
    u_int size_ip;

    eptr = (struct ether_header *) packet;
    my_ip = (struct ip*) (packet+SIZE_ETHERNET);        // skip Ethernet header
    size_ip = my_ip->ip_hl*4;                           // length of IP header
    
    switch (ntohs(eptr->ether_type)){               // see /usr/include/net/ethernet.h for types
        case ETHERTYPE_IP: // IPv4 packet

            //TODO  printf("\tEthernet type is  0x%x, i.e. IP packet \n", ntohs(eptr->ether_type));           
            /*TODO
            printf("\tIP: id 0x%x, hlen %d bytes, version %d, total length %d bytes, TTL %d\n",ntohs(my_ip->ip_id),size_ip,my_ip->ip_v,ntohs(my_ip->ip_len),my_ip->ip_ttl);
            printf("\tIP src = %s, ",inet_ntoa(my_ip->ip_src));
            printf("IP dst = %s",inet_ntoa(my_ip->ip_dst));
            */

            if(my_ip->ip_p == 6){
                struct tcphdr *my_tcp = (struct tcphdr *) (packet+SIZE_ETHERNET+size_ip); // pointer to the TCP header
                tcp_handler(my_tcp);
            }
            break;
        
        case ETHERTYPE_IPV6:  // IPv6 packet
            //TODO  printf("\tEthernet type is 0x%x, i.e., IPv6 packet\n",ntohs(eptr->ether_type));

            if(my_ip->ip_p == 6){
                struct tcphdr *my_tcp = (struct tcphdr *) (packet+SIZE_ETHERNET+size_ip); // pointer to the TCP header
                tcp_handler(my_tcp);
            }
            break;
        default:
            break;
    } 
}

char* getHandlerOnline(char* interfaceName){
    pcap_t* handler;
    pcap_if_t* alldev;
    char* errbuf;
    if(pcap_findalldevs(&alldev, errbuf)){
        return ERR_INPUT_DEVICE;
    }
    do{
        if(!strcmp(alldev->name, interfaceName)){
            if((handler = pcap_open_live(interfaceName, BUFSIZ, 1, 1000, errbuf)) == NULL){
                return ERR_OPEN_LIVE;
            }else{
                if (pcap_loop(handler,-1,mypcap_handler,NULL) == -1){
                    return ERR_PCAP_LOOP;
                }
                pcap_close(handler);
                pcap_freealldevs(alldev);
                return ERR_OK;
            }
        }
        alldev = alldev->next;
    }while(alldev != NULL);
    return ERR_WRONG_INPUT_DEVICE;
}

char* getHandlerOffline(char* fileName){
    pcap_t* handler;
    char* errbuf;
    if((handler = pcap_open_offline(fileName, errbuf)) == NULL){
        return ERR_OPEN_FILE;
    }
    if (pcap_loop(handler,-1,mypcap_handler,NULL) == -1){
        return ERR_PCAP_LOOP;
    }
    pcap_close(handler);
    return ERR_OK;
}

/* TODO ulozene pre neskorsie pouzitie (timestamp)
time = localtime(&header.ts.tv_sec);
    strftime(buff1, 30, "%Y-%m-%d %H:%M:%S", time);
    snprintf(buff2, 30, "%s.%06ld", buff1, header.ts.tv_usec);
*/