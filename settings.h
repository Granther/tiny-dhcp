#include "included.h"
#include "obj.h"
#include "dhcppacket.h"

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

    //extern vanilla_dhcppacket_t* lastPackCache;

    extern char* networkInterface;
#endif






