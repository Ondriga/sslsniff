#ifndef HEADER_SSLPARSER_H
#define HEADER_SSLPARSER_H

#define ERR_OK ""
#define ERR_INPUT_DEVICE "Can`t open input device."
#define ERR_WRONG_INPUT_DEVICE "Your network interface can`t be use."
#define ERR_OPEN_LIVE "pcap_open_live() failed."
#define ERR_OPEN_FILE "Can`t open file for reading."
#define ERR_PCAP_LOOP "pcap_loop() failed"

char* getHandlerOnline(char* interfaceName);
char* getHandlerOffline(char* fileName);

#endif
