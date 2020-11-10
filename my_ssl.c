#include "my_ssl.h"
#include <stdlib.h>
#include <string.h>

ssl_con* ssl_constructor(int timestamp, char* client_IP, int client_PORT, char* server_IP, int server_PORT, char* sni, int duration_sec){
    ssl_con* ssl_con_p = (ssl_con*) malloc(sizeof(ssl_con));
    if(ssl_con_p == NULL){
        return NULL;
    }
    ssl_con_p->client_IP = (char*) malloc(sizeof(char)*(strlen(client_IP)+1));
    if(ssl_con_p->client_IP == NULL){
        free(ssl_con_p);
        return NULL;
    }
    ssl_con_p->server_IP = (char*) malloc(sizeof(char)*(strlen(server_IP)+1));
    if(ssl_con_p->server_IP == NULL){
        free(ssl_con_p->client_IP);
        free(ssl_con_p);
        return NULL;
    }
    ssl_con_p->sni = (char*) malloc(sizeof(char)*(strlen(sni)+1));
    if(ssl_con_p->sni == NULL){
        free(ssl_con_p->client_IP);
        free(ssl_con_p->server_IP);
        free(ssl_con_p);
        return NULL;
    }
    ssl_con_p->timestamp = timestamp;
    ssl_con_p->client_IP = client_IP;
    ssl_con_p->client_PORT = client_PORT;
    ssl_con_p->server_IP = server_IP;
    ssl_con_p->server_PORT = server_PORT;
    ssl_con_p->sni = sni;
    ssl_con_p->duration_sec = duration_sec;
    ssl_con_p->next = NULL;
    return ssl_con_p;
}

void ssl_addOnEnd(ssl_con* ssl_con_p, ssl_con* new_ssl){
    ssl_con* tmp = ssl_con_p;
    while (tmp->next != NULL){
        tmp = tmp->next;
    }
    tmp->next = new_ssl;
}

void ssl_destructor_all(ssl_con* ssl_con_p){
    ssl_con* tmp = NULL;
    while (ssl_con_p != NULL){
        free(ssl_con_p->client_IP);
        free(ssl_con_p->server_IP);
        free(ssl_con_p->sni);
        tmp = ssl_con_p->next;
        free(ssl_con_p);
        ssl_con_p = tmp;
    }
}

void ssl_destructor(ssl_con** ssl_con_p, ssl_con* destroyMe){
    ssl_con* tmp = *ssl_con_p;
    if(tmp == destroyMe){
        *ssl_con_p = tmp->next;
        return;
    }
    while(tmp->next != destroyMe){
        tmp = tmp->next;
    }
    tmp->next = destroyMe->next;
    free(destroyMe->client_IP);
    free(destroyMe->server_IP);
    free(destroyMe->sni);
    free(destroyMe);
}
