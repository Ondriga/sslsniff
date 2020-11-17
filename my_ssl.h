#ifndef HEADER_MY_SSL_H
#define HEADER_MY_SSL_H

#include <stdbool.h>

typedef struct ssl_connection{
    char* timestamp;
    char* client_IP;
    int client_PORT;
    char* server_IP;
    int server_PORT;
    char* sni;
    int bytes;
    int packets;
    double duration_sec;
    bool client_hello;
    bool server_hello;
    int fin_PORT;
    struct ssl_connection* next;
}ssl_con;

ssl_con* ssl_constructor(char* timestamp, char* client_IP, int client_PORT, char* server_IP, int server_PORT, double duration_sec);
void ssl_addOnEnd(ssl_con* ssl_con_p, ssl_con* new_ssl);
void ssl_destructor_all(ssl_con* ssl_con_p);
void ssl_destructor(ssl_con** ssl_con_p, ssl_con* destroyMe);
bool ssl_addSNI(ssl_con* ssl_con_p, char* sni);

#endif
