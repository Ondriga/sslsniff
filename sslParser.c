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

#define SIZE_ETHERNET 14 //offset of Ethernet header to L3 protocol

int read_2_byte(const u_char* number_location){
    return htons(*number_location) + (*(number_location+1));
}

bool load_sni(ssl_con* ssl_con_p, const u_char* ssl_content){
    int tmp = 37;   //Tmp contain number of bytes before attribute session ID length.
    tmp += *(ssl_content+tmp);
    tmp += 1;  //Tmp contain number of bytes before attribute cipher suites length.
    tmp += read_2_byte(ssl_content+tmp);
    tmp += 2;   //Tmp contain number of bytes before attribute compression methods length.
    tmp += *(ssl_content+tmp);
    tmp += 10;   //Tmp contain number of bytes before server name length.
    int name_length = read_2_byte(ssl_content+tmp);
    tmp += 2;   //Tmp contain number of bytes before server name.
    char server_name[name_length+1];
    for(int i=0; i<name_length; i++){
        server_name[i] = *(ssl_content+tmp+i);
    }
    server_name[name_length] = '\0';
    return ssl_addSNI(ssl_con_p, server_name);
}

bool comp_device(char* ip1, int port1, char* ip2, int port2){
    return (strcmp(ip1, ip2) == 0 && port1 == port2);
}

bool comp_ssl_com(ssl_con* ssl_con_p, char* src_IP, int src_PORT, char* dest_IP, int dest_PORT){
    if(comp_device(ssl_con_p->client_IP, ssl_con_p->client_PORT, src_IP, src_PORT) &&
    comp_device(ssl_con_p->server_IP, ssl_con_p->server_PORT, dest_IP, dest_PORT)){
        return true;
    }
    if(comp_device(ssl_con_p->client_IP, ssl_con_p->client_PORT, dest_IP, dest_PORT) &&
    comp_device(ssl_con_p->server_IP, ssl_con_p->server_PORT, src_IP, src_PORT)){
        return true;
    }
    return false;
}

ssl_con* find_ssl(ssl_con* ssl_list, char* src_IP, int src_PORT, char* dest_IP, int dest_PORT){
    for(ssl_con* tmp = ssl_list; tmp != NULL; tmp = tmp->next){
        if(comp_ssl_com(tmp, src_IP, src_PORT, dest_IP, dest_PORT)){
            return tmp;
        }
    }
    return NULL;
}

char* tcp_handler(struct tcphdr *my_tcp, char* timestamp, struct tm* time, char* src_IP, char* dest_IP, const u_char* ssl_header, ssl_con** ssl_list){
    int src_PORT = ntohs(my_tcp->th_sport);
    int dest_PORT = ntohs(my_tcp->th_dport);
    ssl_con* ssl_con_p = NULL;

    if((my_tcp->th_flags & TH_SYN) && !(my_tcp->th_flags & TH_ACK)){
        ssl_con* tmp = ssl_constructor(timestamp, src_IP, src_PORT, dest_IP, dest_PORT, mktime(time));
        if(tmp == NULL){
            return ERR_MALLOC;
        }
        if(*ssl_list == NULL){
            *ssl_list = tmp;
        }else{
            ssl_addOnEnd(*ssl_list, tmp);
        }
        
    }
    if((my_tcp->th_flags & TH_PUSH) && (my_tcp->th_flags & TH_ACK)){
        ssl_con_p = find_ssl(*ssl_list, src_IP, src_PORT, dest_IP, dest_PORT);
        int ssl_bytes;
        const u_char* tmp = ssl_header;
        
        if(ssl_con_p != NULL){
            switch(*ssl_header){
                case 22:
                    if(*(ssl_header+5) == 1){   //If it is Client Hello.
                        if(!load_sni(ssl_con_p, ssl_header+6)){
                            return ERR_MALLOC;
                        }                   
                    }
                case 20:
                case 21:
                case 23:
                    ssl_con_p->packets++;
                    ssl_bytes = htons(*(ssl_header+3)) + (*(ssl_header+4));
                    ssl_con_p->bytes += ssl_bytes;
                    tmp += ssl_bytes + 5;
                    // TODO mozno s tym bude problem
                    while (20 <= *tmp && *tmp <= 23){
                        ssl_bytes = htons(*(tmp+3)) + (*(tmp+4));
                        ssl_con_p->bytes += ssl_bytes;
                        tmp += ssl_bytes + 5;
                    }
                    break;
                default:
                    break;
                    printf("NICENIE STOP\n"); //TODO debug
                    ssl_destructor(ssl_list, ssl_con_p);
            }
        }
    }
    if(my_tcp->th_flags & TH_FIN){
        ssl_con_p = find_ssl(*ssl_list, src_IP, src_PORT, dest_IP, dest_PORT);
        if(ssl_con_p->server_PORT != src_PORT){ //Check if it is second FIN.
            return ERR_OK;
        }
        if(ssl_con_p != NULL){
            if(ssl_con_p->sni != NULL){
                printf("%s,", ssl_con_p->timestamp);
                printf("%s,", ssl_con_p->client_IP);
                printf("%d,", ssl_con_p->client_PORT);
                printf("%s,", ssl_con_p->server_IP);
                printf("%s,", ssl_con_p->sni);
                printf("%d,", ssl_con_p->bytes);
                printf("%d,", ssl_con_p->packets);
                printf("%d", (mktime(time) - ssl_con_p->duration_sec));
                printf("\n");
            }
            ssl_destructor(ssl_list, ssl_con_p);
        }
    }
    return ERR_OK;
}

char* mypcap_handler(const struct pcap_pkthdr header, const u_char *packet, ssl_con** ssl_list){
    struct ip *my_ip;               // pointer to the beginning of IP header
    struct ether_header *eptr;      // pointer to the beginning of Ethernet header
    u_int size_ip;

    const u_char* tcp_header;
    struct tcphdr *my_tcp; // pointer to the TCP header

    int size_TCP; //size of TCP header
    const u_char* ssl_header; //skip to ssl header 

    eptr = (struct ether_header *) packet;

    char tmp[30];
    char timestamp[30];
    struct tm* time = localtime(&header.ts.tv_sec);
    strftime(tmp, 30, "%Y-%m-%d %H:%M:%S", time);
    snprintf(timestamp, 30, "%s.%06ld", tmp, header.ts.tv_usec);

    my_ip = (struct ip*) (packet+SIZE_ETHERNET);        // skip Ethernet header
    size_ip = my_ip->ip_hl*4;                           // length of IP header

    char src_IP[strlen(inet_ntoa(my_ip->ip_src))+1]; 
    char dest_IP[strlen(inet_ntoa(my_ip->ip_dst))+1];
    strcpy(src_IP, inet_ntoa(my_ip->ip_src));
    strcpy(dest_IP, inet_ntoa(my_ip->ip_dst));
    
    switch (ntohs(eptr->ether_type)){
        case ETHERTYPE_IP: // IPv4 packet        
            
            tcp_header = packet+SIZE_ETHERNET+size_ip;
            my_tcp = (struct tcphdr *) tcp_header;
            if(my_ip->ip_p == 6){
                size_TCP = (*(tcp_header+12) & 0xf0) >> 2;
                ssl_header = tcp_header + size_TCP;       
                return tcp_handler(my_tcp, timestamp, time, src_IP, dest_IP, ssl_header, ssl_list);
            }
            break;
        
        case ETHERTYPE_IPV6:  // IPv6 packet
            /*TODO treba dorobit

            //TODO  printf("\tEthernet type is 0x%x, i.e., IPv6 packet\n",ntohs(eptr->ether_type));
            my_ip = (struct ip*) (packet+SIZE_ETHERNET);        // skip Ethernet header
            size_ip = my_ip->ip_hl*4;                           // length of IP header
            src_IP = inet_ntoa(my_ip->ip_src);
            dest_IP = inet_ntoa(my_ip->ip_dst);

            tcp_header = packet+SIZE_ETHERNET+size_ip;
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

                tcp_handler(my_tcp, src_IP, dest_IP, ssl_header, ssl_list);    
            }
            */

            break;
        default:
            break;
    }
    return ERR_OK;
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
                    char* err_value = mypcap_handler(header, packet, &ssl_list);
                    if(strlen(err_value) != 0){
                        pcap_close(handler);
                        pcap_freealldevs(alldev);
                        ssl_destructor_all(ssl_list);
                        return err_value;
                    }
                }
                pcap_close(handler);
                pcap_freealldevs(alldev);
                ssl_destructor_all(ssl_list);
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
        char* err_value = mypcap_handler(header, packet, &ssl_list);
        if(strlen(err_value) != 0){
            pcap_close(handler);
            ssl_destructor_all(ssl_list);
            return err_value;
        }
    }
    pcap_close(handler);
    ssl_destructor_all(ssl_list);
    return ERR_OK;
}

/* TODO ulozene pre neskorsie pouzitie (timestamp)
time = localtime(&header.ts.tv_sec);
    strftime(buff1, 30, "%Y-%m-%d %H:%M:%S", time);
    snprintf(buff2, 30, "%s.%06ld", buff1, header.ts.tv_usec);
*/
