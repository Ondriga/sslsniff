/*
 * Source code for ISA project.
 * file: sslParser.h
 * 
 * (C) Patrik Ondriga (xondri08) 
 */

#ifndef HEADER_SSLPARSER_H
#define HEADER_SSLPARSER_H

//error constants
#define ERR_OK ""   //Everithing is fine.
#define ERR_INPUT_DEVICE "Can`t open input device."
#define ERR_WRONG_INPUT_DEVICE "Your network interface can`t be use."
#define ERR_OPEN_LIVE "pcap_open_live() failed."
#define ERR_OPEN_FILE "Can`t open file for reading."
#define ERR_MALLOC "Problem with malloc function."

/**
 * Start sniffing on specific interface.
 * @param interfaceName interface name.
 * @return one of error constants.
 */
char* getHandlerOnline(char* interfaceName);

/**
 * Start analazing specific pcapng file.
 * @param fileName pcapng file name.
 * @return one of error constants.
 */
char* getHandlerOffline(char* fileName);

#endif
