#include "sslParser.h"
#include "my_ssl.h"
#include <string.h>

#include <pcap.h>
#include <netinet/ip.h>

#include <pcap/pcap.h>
#include <errno.h>
#include <sys/socket.h>
#define __FAVOR_BSD // important for tcphdr structure
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <arpa/inet.h>
#include <netinet/if_ether.h> 
#include <err.h>

#ifdef __linux__ // for Linux
#include <netinet/ether.h> 
#include <time.h>
#include <pcap/pcap.h>
#endif

#define SIZE_IPv4_ETHERNET 14 //offset of IPv4 Ethernet header to L3 protocol
#define SIZE_IPv6_ETHERNET 13 //offset of IPv6 Ethernet header to L3 protocol

void tcp_handler(struct tcphdr *my_tcp, const u_char *packet, char* src_IP, char* dest_IP, const u_char* ssl_header){
    if(my_tcp->th_flags & TH_SYN){
        //TODO zaciatok komunikacie
        int src_PORT = ntohs(my_tcp->th_sport);
        int dest_PORT = ntohs(my_tcp->th_dport);
    }
    if((my_tcp->th_flags & TH_PUSH) && (my_tcp->th_flags & TH_ACK)){
        //TODO kontrola, ci je ssl, ak je, potom spracuj
        int length = htons(*(ssl_header+3)) + (*(ssl_header+4));
    }
    if(my_tcp->th_flags & TH_FIN){
        //TODO ukoncit a vyhodnotit
    }
}

void mypcap_handler(const struct pcap_pkthdr header, const u_char *packet, ssl_con* ssl_list){
    struct ip *my_ip;               // pointer to the beginning of IP header
    struct ether_header *eptr;      // pointer to the beginning of Ethernet header
    u_int size_ip;

    char* src_IP;
    char* dest_IP;
    const u_char* tcp_header;
    struct tcphdr *my_tcp; // pointer to the TCP header

    int size_TCP; //size of TCP header
    const u_char* ssl_header; //skip to ssl header 

    eptr = (struct ether_header *) packet;

    switch (ntohs(eptr->ether_type)){
        case ETHERTYPE_IP: // IPv4 packet
            my_ip = (struct ip*) (packet+SIZE_IPv4_ETHERNET);        // skip Ethernet header
            size_ip = my_ip->ip_hl*4;                           // length of IP header
            src_IP = inet_ntoa(my_ip->ip_src);
            dest_IP = inet_ntoa(my_ip->ip_dst);

            tcp_header = packet+SIZE_IPv4_ETHERNET+size_ip;
            my_tcp = (struct tcphdr *) tcp_header;

            if(my_ip->ip_p == 6){
                size_TCP = (*(tcp_header+12) & 0xf0) >> 2;
                ssl_header = tcp_header + size_TCP;           
                tcp_handler(my_tcp, packet, src_IP, dest_IP, ssl_header);
            }
            break;
        
        case ETHERTYPE_IPV6:  // IPv6 packet
            /*TODO treba dorobit

            //TODO  printf("\tEthernet type is 0x%x, i.e., IPv6 packet\n",ntohs(eptr->ether_type));
            my_ip = (struct ip*) (packet+SIZE_IPv6_ETHERNET);        // skip Ethernet header
            size_ip = my_ip->ip_hl*4;                           // length of IP header
            src_IP = inet_ntoa(my_ip->ip_src);
            dest_IP = inet_ntoa(my_ip->ip_dst);

            tcp_header = packet+SIZE_IPv6_ETHERNET+size_ip;
            my_tcp = (struct tcphdr *) tcp_header;
            printf("#######################%d#\n", my_ip->ip_p);//TODO debug
            if(my_ip->ip_p == 6){
                

                size_TCP = (*(tcp_header+12) & 0xf0) >> 2;
                ssl_header = tcp_header + size_TCP;

                printf("############################ %d ##########################\n", size_TCP);
                printf("1.##%d##\n", *(ssl_header+3));
                printf("2.##%d##\n", *(ssl_header+4));
                printf("1+2##%d##\n", ((*(ssl_header+3))+(*(ssl_header+4))));
                short length = htons(*(ssl_header+3)) + (*(ssl_header+4));
                printf("length = %d\n\n", length);

                tcp_handler(my_tcp, packet, src_IP, dest_IP, ssl_header);    
            }
            */

            break;
        default:
            break;
    } 
}

char* getHandlerOnline(char* interfaceName){
    ssl_con* ssl_list = NULL;
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
                const u_char *packet;
                struct pcap_pkthdr header;
                while ((packet = pcap_next(handler,&header)) != NULL){
                    mypcap_handler(header, packet, ssl_list);
                }
                pcap_close(handler);
                pcap_freealldevs(alldev);
                ssl_destructor(ssl_list);
                return ERR_OK;
            }
        }
        alldev = alldev->next;
    }while(alldev != NULL);
    return ERR_WRONG_INPUT_DEVICE;
}

char* getHandlerOffline(char* fileName){
    ssl_con* ssl_list = NULL;
    pcap_t* handler;
    char* errbuf;
    if((handler = pcap_open_offline(fileName, errbuf)) == NULL){
        return ERR_OPEN_FILE;
    }
    const u_char *packet;
    struct pcap_pkthdr header;
    while ((packet = pcap_next(handler,&header)) != NULL){
        mypcap_handler(header, packet, ssl_list);
    }
    pcap_close(handler);
    ssl_destructor(ssl_list);
    return ERR_OK;
}

/* TODO ulozene pre neskorsie pouzitie (timestamp)
time = localtime(&header.ts.tv_sec);
    strftime(buff1, 30, "%Y-%m-%d %H:%M:%S", time);
    snprintf(buff2, 30, "%s.%06ld", buff1, header.ts.tv_usec);
*/
