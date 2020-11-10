#ifndef HEADER_MY_SSL_H
#define HEADER_MY_SSL_H

#define SSL_LENGTH = 3;

typedef struct ssl_connection{
    int timestamp;
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

ssl_con* ssl_constructor(int timestamp, char* client_IP, int client_PORT, char* server_IP, int server_PORT, char* sni, int duration_sec);
void ssl_addOnEnd(ssl_con* ssl_con_p, ssl_con* new_ssl);
void ssl_destructor_all(ssl_con* ssl_con_p);
void ssl_destructor(ssl_con** ssl_con_p, ssl_con* destroyMe);

#endif
