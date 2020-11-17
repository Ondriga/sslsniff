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
#define SIZE_IPv6 40 //offset of IPv6 header
#define SIZE_TLS 5 //bytes of tls header

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
    tmp += 3;   //Tmp contain number of bytes before first extension.
    while(read_2_byte(ssl_content+tmp) != 0){
        tmp += 2;   //Tmp contain number of bytes before extension length.
        tmp += read_2_byte(ssl_content+tmp);
        tmp += 2;   //Tmp contain number of bytes before nest extension.
    }
    tmp += 7;   //Tmp contain number of bytes before server name length.
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

bool is_tls(const u_char* header){
    if(20 <= *header && *header <= 23){
        if(*(header+1) == 3){
            if(1 <= *(header+2) && *(header+2) <= 4){
                return true;
            }
        }
    }
    return false;
}

char* tcp_handler(const u_char* tcp_header, char* timestamp, double time, char* src_IP, char* dest_IP, ssl_con** ssl_list, int payload){
    struct tcphdr *my_tcp = (struct tcphdr *) tcp_header;
    int size_TCP = (*(tcp_header+12) & 0xf0) >> 2; //size of TCP header
    payload -= size_TCP;
    const u_char* ssl_header = tcp_header + size_TCP;

    int src_PORT = ntohs(my_tcp->th_sport);
    int dest_PORT = ntohs(my_tcp->th_dport);
    ssl_con* ssl_con_p = NULL;

    if((my_tcp->th_flags & TH_SYN) && !(my_tcp->th_flags & TH_ACK)){
        ssl_con* tmp = ssl_constructor(timestamp, src_IP, src_PORT, dest_IP, dest_PORT, time);
        if(tmp == NULL){
            return ERR_MALLOC;
        }
        if(*ssl_list == NULL){
            *ssl_list = tmp;
        }else{
            ssl_addOnEnd(*ssl_list, tmp);
        }
        
    }else if(my_tcp->th_flags & TH_FIN){
        ssl_con_p = find_ssl(*ssl_list, src_IP, src_PORT, dest_IP, dest_PORT);
        if(ssl_con_p != NULL){
            ssl_con_p->packets++;
            if(ssl_con_p->server_PORT != src_PORT){ //Check if it is second FIN.
                return ERR_OK;
            }
            if(ssl_con_p->sni != NULL){
                printf("%s,", ssl_con_p->timestamp);
                printf("%s,", ssl_con_p->client_IP);
                printf("%d,", ssl_con_p->client_PORT);
                printf("%s,", ssl_con_p->server_IP);
                printf("%s,", ssl_con_p->sni);
                printf("%d,", ssl_con_p->bytes);
                printf("%d,", ssl_con_p->packets);
                printf("%f", (time - ssl_con_p->duration_sec));
                printf("\n");
            }
            ssl_destructor(ssl_list, ssl_con_p);
        }
    }else{
        ssl_con_p = find_ssl(*ssl_list, src_IP, src_PORT, dest_IP, dest_PORT);
        if(ssl_con_p != NULL){
            ssl_con_p->packets++;
            for(int offset=0; offset<payload-4; offset++){
                if(is_tls(ssl_header+offset)){
                    ssl_con_p->bytes += read_2_byte(ssl_header+offset+3);
                    if(*(ssl_header+offset) == 22 && *(ssl_header+offset+SIZE_TLS) == 1){
                        if(!load_sni(ssl_con_p, ssl_header+offset+6)){
                            return ERR_MALLOC;
                        }
                    }
                }
            }
        }
    }    
    return ERR_OK;
}

char* mypcap_handler(const struct pcap_pkthdr header, const u_char *packet, ssl_con** ssl_list){
    struct ether_header *eptr = (struct ether_header *) packet; // pointer to the beginning of Ethernet header
    int payload = header.caplen - SIZE_ETHERNET;
    char tmp[30];
    char timestamp[30];
    struct tm* time = localtime(&header.ts.tv_sec);
    strftime(tmp, 30, "%Y-%m-%d %H:%M:%S", time);
    snprintf(timestamp, 30, "%s.%06ld", tmp, header.ts.tv_usec);

    double seconds = mktime(time) + header.ts.tv_usec/1000000.0;
    
    if(ntohs(eptr->ether_type) == ETHERTYPE_IP){ // IPv4 packet  
        struct ip *ipv4_header = (struct ip*) (packet+SIZE_ETHERNET); // pointer to the beginning of IPv4 header
        if(ipv4_header->ip_p == 6){ //If next is TCP header
            u_int size_ip = ipv4_header->ip_hl*4;   // length of IPv4 header
            const u_char* tcp_header = packet+SIZE_ETHERNET+size_ip;

            char src_IP[strlen(inet_ntoa(ipv4_header->ip_src))+1]; 
            char dest_IP[strlen(inet_ntoa(ipv4_header->ip_dst))+1];
            strcpy(src_IP, inet_ntoa(ipv4_header->ip_src));
            strcpy(dest_IP, inet_ntoa(ipv4_header->ip_dst));
       
            return tcp_handler(tcp_header, timestamp, seconds, src_IP, dest_IP, ssl_list, payload-size_ip);
        }
    }else if(ntohs(eptr->ether_type) == ETHERTYPE_IPV6){  // IPv6 packet
        const u_char* ipv6_header = packet+SIZE_ETHERNET; // pointer to the beginning of IPv6 header
        if(*(ipv6_header+6) == 6){ //If next is TCP header
            const u_char* tcp_header = packet+SIZE_ETHERNET+SIZE_IPv6;

            char src_IP[INET6_ADDRSTRLEN]; 
            char dest_IP[INET6_ADDRSTRLEN];
            inet_ntop(AF_INET6, ipv6_header+8, src_IP, INET6_ADDRSTRLEN);
            inet_ntop(AF_INET6, ipv6_header+24, dest_IP, INET6_ADDRSTRLEN);

            return tcp_handler(tcp_header, timestamp, seconds, src_IP, dest_IP, ssl_list, payload-SIZE_IPv6);
        }
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
