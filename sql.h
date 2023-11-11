#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <stdbool.h>
#include <sys/stat.h>
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
#include "obj.h"
#include "settings.h"

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
    int sqlDBConnectTest();
#endif 





