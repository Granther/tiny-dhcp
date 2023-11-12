#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <time.h>
#include <netdb.h>
#include <stdint.h>
#include <libpq-fe.h>
#include <math.h>
#include <sys/stat.h>
#include <dirent.h>
#include <ctype.h>
#include <limits.h>
#include <unistd.h>
#include <signal.h>
#include <syslog.h>
#include "sql.h"
#include "obj.h" 
#include "settings.h"

#ifndef UTILITY_H
    #define UTILITY_H
    void clearOptionArr();
    uint32_t maskToSubnet(int mask);
    uint32_t ipToVal(char* ip);
    char* cutOffSub(char* ipWithSb);
    long howManyIps(int bitMask);
    void emptyIt(uint8_t* arrPtr, int len);
    int arrUint8Empty(uint8_t arr[], size_t s);
    char* mac6ToString(uint8_t macAddress[6]);
    uint8_t getLenWithOpCode(uint8_t options[GLOBAL_OPTIONS_LEN], uint8_t opCode);
    void genHostAddr(const char *sub, int bits);
    int getUnleasedIp(char* unleasedRet);
    void emptyIt(uint8_t* arrPtr, int len);

    int u8ToMacStr(uint8_t* macHex, char* str);
    int u32ToIpStr(uint32_t hex32, char* ip);
    uint32_t ipStrToU32(char* ip);
    int ipStrToU8(char* str, uint8_t* list);
    int u32ToU8Be(uint32_t ip32, uint8_t* list8);
    void printIp(uint32_t ip);
    uint32_t u8ToU32(uint8_t* list);
    int u8ToIpStr(uint8_t *list, char* str);

    void cutMac(uint8_t* mac);

#endif
 
