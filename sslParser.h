#include <pcap.h>

const int ERR_OK = 0;
const int ERR_INPUT_DEVICE = 1;
const int ERR_WRONG_INPUT_DEVICE =2;
const int ERR_OPEN_LIVE = 3;
const int ERR_OPEN_FILE = 4;

int getHandlerOnline(char* interfaseName, pcap_t** handler);
int getHandlerOffline(char* fileName, pcap_t** handler);
