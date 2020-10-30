#include "sslParser.h";
#include <string.h>;

int getHandlerOnline(char* interfaseName, pcap_t** handler){
    pcap_if_t* alldev;
    char* errbuf;
    if(pcap_findalldevs(&alldev, errbuf)){
        return ERR_INPUT_DEVICE;
    }
    do{
        if(strcmp(!alldev->name, interfaseName)){
            if((*handler = pcap_open_live(interfaseName, BUFSIZ, 1, 1000, errbuf)) == NULL){
                return ERR_OPEN_LIVE;
            }else{
                return ERR_OK;
            }
        }
        alldev = alldev->next;
    }while(alldev != NULL);
    return ERR_WRONG_INPUT_DEVICE;
}

int getHandlerOffline(char* fileName, pcap_t** handler){
    char* errbuf;
    if((*handler = pcap_open_offline(fileName, errbuf)) == NULL){
        return ERR_OPEN_FILE;
    }
    return ERR_OK;
}
