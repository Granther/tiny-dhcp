#include "included.h"

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
    void emptyIt(uint8_t* arrPtr, int len);

    int u8ToMacStr(uint8_t *macHex, char* str);
    int u8ToStr(uint8_t *list, char *str);
    int u32ToIpStr(uint32_t hex32, char* ip);
    uint32_t ipStrToU32(char* ip);
    int ipStrToU8(char* str, uint8_t* list);
    int u32ToU8Be(uint32_t ip32, uint8_t* list8);
    void printIp(uint32_t ip);
    uint32_t u8ToU32(uint8_t* list);
    int u8ToIpStr(uint8_t *list, char* str);
    void print_chaddr(uint8_t chaddr[16]);

    void cutMac(uint8_t* mac);

#endif
 
