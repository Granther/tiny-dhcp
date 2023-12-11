#include "included.h"
#include "obj.h"

#ifndef SQL_H
    #define SQl_H
    int leaseToDB(LeasedClient* lcPtr);
    int sendSQL(char* command);
    int removeLeaseByIp(char* leasedIp);
    int arrUint8EmptySql(uint8_t arr[], size_t s);
    bool checkIfLeased(char* ip);
    int checkForDuplicateLeases();
    int clearAllLeases();
    char* genConnStr();
    bool checkIfMacHasLease(char* mac);
    int sqlDBConnectTest();
    int getUnleasedIp(char* unleasedRet, int bits);
#endif 




