#ifndef HEADER_MY_SSL_H
#define HEADER_MY_SSL_H

#include <stdbool.h>

#define SSL_LENGTH = 3;

typedef struct ssl_connection{
    char* timestamp;
    char* client_IP;
    int client_PORT;
    char* server_IP;
    int server_PORT;
    char* sni;
    int bytes;
    int packets;
    int duration_sec;
    struct ssl_connection* next;
}ssl_con;

ssl_con* ssl_constructor(char* timestamp, char* client_IP, int client_PORT, char* server_IP, int server_PORT, int duration_sec);
void ssl_addOnEnd(ssl_con* ssl_con_p, ssl_con* new_ssl);
void ssl_destructor_all(ssl_con* ssl_con_p);
void ssl_destructor(ssl_con** ssl_con_p, ssl_con* destroyMe);
bool ssl_addSNI(ssl_con* ssl_con_p, char* sni);

#endif
