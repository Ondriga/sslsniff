/*
 * Source code for ISA project.
 * file: my_ssl.h
 * 
 * (C) Patrik Ondriga (xondri08) 
 */

#ifndef HEADER_MY_SSL_H
#define HEADER_MY_SSL_H

#include <stdbool.h>

#define SIZE_TLS 5 //bytes of tls header

/**
 * These struct represent one ssl connection.
 */
typedef struct ssl_connection{
    char* timestamp;                /**< timestamp */
    char* client_IP;                /**< client IP address */
    int client_PORT;                /**< client PORT number */
    char* server_IP;                /**< server IP address */
    int server_PORT;                /**< server PORT number */
    char* sni;                      /**< SNI */
    int bytes;                      /**< all tls bytes */
    int packets;                    /**< number for receve and sending packets */
    double duration_sec;            /**< connection duration in seconds */
    bool client_hello;              /**< flag for client hello */
    bool server_hello;              /**< flag for server hello */
    int fin_PORT;                   /**< source PORT number of first FIN packet */
    struct ssl_connection* next;    /**< pointer to next ssl structure */
}ssl_con;

/**
 * Constructor for ssl structure. Allocate and fill ssl structure.
 * @param timestamp timestamp.
 * @param client_IP client IP address.
 * @param client_PORT client PORT number.
 * @param server_IP server IP address.
 * @param serveer_PORT server PORT number.
 * @param duration_sec time when arrived first packet in second.
 * @return if malloc was successful pointer to the ssl structure, otherwise null.
 */
ssl_con* ssl_constructor(char* timestamp, char* client_IP, int client_PORT, char* server_IP, int server_PORT, double duration_sec);

/**
 * Write ssl structure on the end of ssl list. If ssl list is empty, then ssl_con_p will pointing on new_ssl.
 * @param ssl_con_p pointer on list of ssl structures.
 * @param new_ssl pointer on ssl structure which we want to add to ssl list.
 */
void ssl_addOnEnd(ssl_con* ssl_con_p, ssl_con* new_ssl);

/**
 * Dealocate whole ssl list.
 * @param ssl_con_p list of ssl structures.
 */
void ssl_destructor_all(ssl_con* ssl_con_p);

/**
 * Remove and dealocate one ssl structure from list.
 * @param ssl_con_p pointer on list of ssl structures.
 * @param destryMe pointer on ssl struct for destroy.
 */
void ssl_destructor(ssl_con** ssl_con_p, ssl_con* destroyMe);

/**
 * Allocate space for SNI and store them.
 * @param ssl_con_p pointer on ssl struct.
 * @param sni SNI.
 */
bool ssl_addSNI(ssl_con* ssl_con_p, char* sni);

#endif
