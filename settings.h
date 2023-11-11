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

#ifndef SETTINGS_H
    #define SETTINGS_h
    int readSetting(char* buf, char* value, char* settingName);
    int createSettings();
    int changeSetting(char* argList[256]);
    int copyToOld();
    bool fileNull(FILE* file);
    bool confSameOld();
    int getValFromSet(char* setName, char* setting);
    void settingInit();

    extern Settings *sqlSet; 
    extern Settings set;

    extern uint8_t subnetMask[16];
    extern uint8_t router[16];
    extern uint8_t dns[16];
    extern uint8_t serverIdent[16];
    extern uint32_t roleModel;

    extern char* networkInterface;
#endif

/*
sqlSet.database_name = (char *)malloc(MAX_STRING_LENGTH * sizeof(char));
    sqlSet.leases_name = (char *)malloc(MAX_STRING_LENGTH * sizeof(char));
    sqlSet.user_name = (char *)malloc(MAX_STRING_LENGTH * sizeof(char));
    sqlSet.password = (char *)malloc(MAX_STRING_LENGTH * sizeof(char));
    sqlSet.host = (char *)malloc(MAX_STRING_LENGTH * sizeof(char));

    // Check if memory allocation was successful
    if (sqlSet.database_name == NULL || sqlSet.leases_name == NULL || sqlSet.user_name == NULL ||
        sqlSet.password == NULL || sqlSet.host == NULL) {
        fprintf(stderr, "Error - Memory allocation failed\n");
        exit(EXIT_FAILURE);
    }

    strcpy(sqlSet.database_name, getValFromSet("database-name"));
    strcpy(sqlSet.leases_name, getValFromSet("leases-name"));
    strcpy(sqlSet.user_name, getValFromSet("user-name"));
    strcpy(sqlSet.password, getValFromSet("password"));
    strcpy(sqlSet.host, getValFromSet("host"));*/





