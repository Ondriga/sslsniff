#include "my_ssl.h"
#include <stdlib.h>

ssl_con* ssl_constructor(){
    ssl_con* ssl_con_p = (ssl_con*) malloc(sizeof(ssl_con));
    if(ssl_con_p == NULL){
        return NULL;
    }
    ssl_con_p->client_IP = (char*) malloc(sizeof(char)*50);
    if(ssl_con_p->client_IP == NULL){
        free(ssl_con_p);
        return NULL;
    }
    ssl_con_p->server_IP = (char*) malloc(sizeof(char)*50);
    if(ssl_con_p->server_IP == NULL){
        free(ssl_con_p->client_IP);
        free(ssl_con_p);
        return NULL;
    }
    ssl_con_p->sni = (char*) malloc(sizeof(char)*50);
    if(ssl_con_p->sni == NULL){
        free(ssl_con_p->client_IP);
        free(ssl_con_p->server_IP);
        free(ssl_con_p);
        return NULL;
    }
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

void ssl_destructor(ssl_con* ssl_con_p){
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