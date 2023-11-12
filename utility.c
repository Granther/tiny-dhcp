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
#include "utility.h"

int u8ToMacStr(uint8_t* macHex, char* str) { // untested
    if (str == NULL) {
        fprintf(stderr, "NULL Pointer to string when converting mac addr\n");
        return 1;
    }

    sprintf(str, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
    macHex[0], macHex[1], macHex[2],
    macHex[3], macHex[4], macHex[5]);

    return 0;
}

int u32ToIpStr(uint32_t hex32, char* ip) {
    
    snprintf(ip, sizeof(ip), "%u", hex32);
}

int u8ToIpStr(uint8_t *list, char* str) {
    sprintf(str, "%u.%u.%u.%u", list[0], list[1], list[2], list[3]);
}

uint32_t ipStrToU32(char* ip) {
    uint32_t hex32;

    if (inet_pton(AF_INET, ip, &hex32) != 1) {
        fprintf(stderr, "Failed to convert ip string to uint 32 hex\n");
        return 1;
    }

    return hex32;
}

int ipStrToU8(char* str, uint8_t* list) {
    if (u32ToU8Be(ipStrToU32(str), list) != 0)
    {
        fprintf(stderr, "Error - Problem converting string to uin8_t list\n");
        return 1;
    }

    return 0;
}

uint32_t u8ToU32(uint8_t* list) {
    return ((uint32_t)list[0]) | ((uint32_t)list[1] << 8) | ((uint32_t)list[2] << 16) | ((uint32_t)list[3] << 24); 
}

int u32ToU8Be(uint32_t ip32, uint8_t* list8) {

    list8[3] = (ip32 >> 24) & 0xFF;
    list8[2] = (ip32 >> 16) & 0xFF;
    list8[1] = (ip32 >> 8) & 0xFF;
    list8[0] = ip32 & 0xFF;

    return 0;
}

void printIp(uint32_t ip) {
    uint8_t octet1 = (ip >> 24) & 0xFF;
    uint8_t octet2 = (ip >> 16) & 0xFF;
    uint8_t octet3 = (ip >> 8) & 0xFF;
    uint8_t octet4 = ip & 0xFF;

    printf("%u.%u.%u.%u\n", octet4, octet3, octet2, octet1);
}

char* cutOffSub(char* ipWithSb) {
    int l = strlen(ipWithSb) - 3;
    char* ip[24];
    
    for (int i = 0; i < l; i++) {
        char item = ipWithSb[i];



        if (item == '/') {
            return *ip;
        }   

        ip[i] = &item;
    }

    //return *ip;
}
uint32_t ipToVal(char* ip) {
    struct in_addr addr;
    inet_pton(AF_INET, ip, &addr);
    return ntohl(addr.s_addr);
}

int arrUint8Empty(uint8_t arr[], size_t s) { // 1 if not empty 0 if empty
    for (size_t i = 0; i < s; i++) {
        if (arr[i] != 0) {
            return 1;
        }
    }
    return 0;
}

void genHostAddr(const char *sub, int bits) {

    uint32_t netAddr = roleModel << 8;
    
    for (int i = 0; i < (1<< (32 - bits)); i++) {
        uint32_t ipAddr = netAddr + i;

        printf("%u.%u.%u.%u\n", 
        (ipAddr >> 24) & 0xFF,
        (ipAddr >> 16) & 0xFF,
        (ipAddr >> 8) & 0xFF,
        ipAddr & 0xFF);
    }
}

uint8_t getLenWithOpCode(uint8_t options[GLOBAL_OPTIONS_LEN], uint8_t opCode) 
{
    for (size_t i = 0; i < GLOBAL_OPTIONS_LEN; i++) 
    {
        if (options[i] == opCode) {
            return options[i+1];
        }
    }
}

uint32_t maskToSubnet(int mask) {
    if (mask < 0 || mask > 32) {
        fprintf(stderr, "The subnet mask is either under 0 bits or over 32 bits\n");
        return 1;
    }

    return ((uint32_t)0xFFFFFFFF) << (32 - mask);
}


uint8_t* readData(DhcpPacket *pack, int ind) {
    int len = pack->options[ind + 1];
    uint8_t* opArr = (uint8_t*)malloc(216 * sizeof(uint8_t));
    int j = 0;
    for (int i = ind; i < (ind + len); i++) {
        opArr[j] = pack->options[i + 2];
        j++;
    }

    return opArr;
}

void cutMac(uint8_t* mac) 
{
    for (int i = 0; i < sizeof(mac) - 1; i++) {
        mac[i] = mac[i + 1];
    }
}


char* mac6ToString(uint8_t macAddress[7]) {
    char* res;
    sprintf(res, "%02X%02X%02X%02X%02X%02X",
            macAddress[0], macAddress[1], macAddress[2],
            macAddress[3], macAddress[4], macAddress[5]);

    return res;
}

void writeTest() {
    FILE *file = fopen("/home/grant/Desktop/dhcp.txt", "w");
    fprintf(file, "test1");
    fclose(file);
}

// uin32_t to uin8_t list
// uint8_t list to uint32_t
// uin32_t to string
// uin8_t list to string
// string to uint32_t 
// string to uint8_t list

/*uint8_t* 
thirtytwoToEight(uint32_t u32) 
{
    uint8_t *resArr[4];
    memset(resArr, 0, sizeof(resArr));
    uint8_t list[4];

    list[3] = (u32 >> 24) & 0xFF;
    list[2] = (u32 >> 16) & 0xFF;
    list[1] = (u32 >> 8) & 0xFF;
    list[0] = u32 & 0xFF;

    for (int i = 0; i < 3; i++) {
        resArr[i] = &list[i];
    }

    return *resArr;
}*/

uint32_t 
eightTo32(uint8_t arr[4]) 
{   
    uint32_t result = 0;

    result |= (uint32_t)arr[3] << 24;
    result |= (uint32_t)arr[2] << 16;
    result |= (uint32_t)arr[1] << 8;
    result |= (uint32_t)arr[0];

    return result;
}

/*char*
thritytwoToStr(uint32_t u32) 
{
    char* str;

    snprintf(str, sizeof(u32), "%u", u32);

    return str;
}

char*
eightUint4ToStr(uint8_t list[4]) 
{
    uint32_t *u32 = eightTo32(list);

    return thritytwoToStr(*u32);
}*/




void opReader(size_t opCode) {
    switch (opCode) { 
    case 0: printf("Pad - None\n"); break; 
    case 1: printf("Subnet Mask - Subnet Mask Value\n"); break; 
    case 2: printf("Time Offset - Time Offset in Seconds from UTC (deprecated by 100 and 101)\n"); break; 
    case 3: printf("Router - N/4 Router addresses\n"); break; 
    case 4: printf("Time Server - N/4 Timeserver addresses\n"); break; 
    case 5: printf("Name Server - N/4 IEN-116 Server addresses\n"); break; 
    case 6: printf("Domain Server - N/4 DNS Server addresses\n"); break; 
    case 7: printf("Log Server - N/4 Logging Server addresses\n"); break; 
    case 8: printf("Quotes Server - N/4 Quotes Server addresses\n"); break; 
    case 9: printf("LPR Server - N/4 Printer Server addresses\n"); break; 
    case 10: printf("Impress Server - N/4 Impress Server addresses\n"); break; 
    case 11: printf("RLP Server - N/4 RLP Server addresses\n"); break; 
    case 12: printf("Hostname - Hostname string\n"); break; 
    case 13: printf("Boot File Size - Size of boot file in 512 byte chunks\n"); break; 
    case 14: printf("Merit Dump File - Client to dump and name the file to dump it to\n"); break; 
    case 15: printf("Domain Name - The DNS domain name of the client\n"); break; 
    case 16: printf("Swap Server - Swap Server address\n"); break; 
    case 17: printf("Root Path - Path name for root disk\n"); break; 
    case 18: printf("Extension File - Path name for more BOOTP info\n"); break; 
    case 19: printf("Forward On/Off - Enable/Disable IP Forwarding\n"); break; 
    case 20: printf("SrcRte On/Off - Enable/Disable Source Routing\n"); break; 
    case 21: printf("Policy Filter - Routing Policy Filters\n"); break; 
    case 22: printf("Max DG Assembly - Max Datagram Reassembly Size\n"); break; 
    case 23: printf("Default IP TTL - Default IP Time to Live\n"); break; 
    case 24: printf("MTU Timeout - Path MTU Aging Timeout\n"); break; 
    case 25: printf("MTU Plateau - Path MTU Plateau Table\n"); break; 
    case 26: printf("MTU Interface - Interface MTU Size\n"); break; 
    case 27: printf("MTU Subnet - All Subnets are Local\n"); break; 
    case 28: printf("Broadcast Address - Broadcast Address\n"); break; 
    case 29: printf("Mask Discovery - Perform Mask Discovery\n"); break; 
    case 30: printf("Mask Supplier - Provide Mask to Others\n"); break; 
    case 31: printf("Router Discovery - Perform Router Discovery\n"); break; 
    case 32: printf("Router Request - Router Solicitation Address\n"); break; 
    case 33: printf("Static Route - Static Routing Table\n"); break; 
    case 34: printf("Trailers - Trailer Encapsulation\n"); break; 
    case 35: printf("ARP Timeout - ARP Cache Timeout\n"); break; 
    case 36: printf("Ethernet - Ethernet Encapsulation\n"); break; 
    case 37: printf("Default TCP TTL - Default TCP Time to Live\n"); break; 
    case 38: printf("Keepalive Time - TCP Keepalive Interval\n"); break; 
    case 39: printf("Keepalive Data - TCP Keepalive Garbage\n"); break; 
    case 40: printf("NIS Domain - NIS Domain Name\n"); break; 
    case 41: printf("NIS Servers - NIS Server Addresses\n"); break; 
    case 42: printf("NTP Servers - NTP Server Addresses\n"); break; 
    case 43: printf("Vendor Specific - Vendor Specific Information\n"); break; 
    case 44: printf("NETBIOS Name Srv - NETBIOS Name Servers\n"); break; 
    case 45: printf("NETBIOS Dist Srv - NETBIOS Datagram Distribution\n"); break; 
    case 46: printf("NETBIOS Node Type - NETBIOS Node Type\n"); break; 
    case 47: printf("NETBIOS Scope - NETBIOS Scope\n"); break; 
    case 48: printf("X Window Font - X Window Font Server\n"); break; 
    case 49: printf("X Window Manager - X Window Display Manager\n"); break; 
    case 50: printf("Address Request - Requested IP Address\n"); break; 
    case 51: printf("Address Time - IP Address Lease Time\n"); break; 
    case 52: printf("Overload - Overload 'sname' or 'file'\n"); break; 
    case 53: printf("DHCP Msg Type - DHCP Message Type\n"); break; 
    case 54: printf("DHCP Server Id - DHCP Server Identification\n"); break; 
    case 55: printf("Parameter List - Parameter Request List\n"); break; 
    case 56: printf("DHCP Message - DHCP Error Message\n"); break; 
    case 57: printf("DHCP Max Msg Size - DHCP Maximum Message Size\n"); break; 
    case 58: printf("Renewal Time - DHCP Renewal (T1) Time\n"); break; 
    case 59: printf("Rebinding Time - DHCP Rebinding (T2) Time\n"); break; 
    case 60: printf("Class Id - Class Identifier\n"); break; 
    case 61: printf("Client Id - Client Identifier\n"); break; 
    case 62: printf("NetWare/IP Domain - NetWare/IP Domain Name\n"); break; 
    case 63: printf("NetWare/IP Option - NetWare/IP sub Options\n"); break; 
    case 64: printf("NIS-Domain-Name - NIS+ v3 Client Domain Name\n"); break; 
    case 65: printf("NIS-Server-Addr - NIS+ v3 Server Addresses\n"); break; 
    case 66: printf("Server-Name - TFTP Server Name\n"); break; 
    case 67: printf("Bootfile-Name - Boot File Name\n"); break; 
    case 68: printf("Home-Agent-Addrs - Home Agent Addresses\n"); break; 
    case 69: printf("SMTP-Server - Simple Mail Server Addresses\n"); break; 
    case 70: printf("POP3-Server - Post Office Server Addresses\n"); break; 
    case 71: printf("NNTP-Server - Network News Server Addresses\n"); break; 
    case 72: printf("WWW-Server - WWW Server Addresses\n"); break; 
    case 73: printf("Finger-Server - Finger Server Addresses\n"); break; 
    case 74: printf("IRC-Server - Chat Server Addresses\n"); break; 
    case 75: printf("StreetTalk-Server - StreetTalk Server Addresses\n"); break; 
    case 76: printf("STDA-Server - ST Directory Assist. Addresses\n"); break; 
    case 77: printf("User-Class - User Class Information\n"); break; 
    case 78: printf("Directory Agent - Directory agent information\n"); break; 
    case 79: printf("Service Scope - Service location agent scope\n"); break; 
    case 80: printf("Rapid Commit - Rapid Commit\n"); break; 
    case 81: printf("Client FQDN - Fully Qualified Domain Name\n"); break; 
    case 82: printf("Relay Agent Information - Relay Agent Information\n"); break; 
    case 83: printf("iSNS - Internet Storage Name Service\n"); break; 
    case 84: printf("REMOVED/Unassigned\n"); break; 
    case 85: printf("NDS Servers - Novell Directory Services\n"); break; 
    case 86: printf("NDS Tree Name\n"); break;
    case 87: printf("NDS Context - Novell Directory Services\n"); break; 
    case 88: printf("BCMCS Controller Domain Name list\n"); break; 
    case 89: printf("BCMCS Controller IPv4 address option\n"); break; 
    case 90: printf("Authentication - Authentication\n"); break; 
    case 91: printf("client-last-transaction-time option\n"); break; 
    case 92: printf("associated-ip option\n"); break; 
    case 93: printf("Client System - Client System Architecture\n"); break; 
    case 94: printf("Client NDI - Client Network Device Interface\n"); break; 
    case 95: printf("LDAP - Lightweight Directory Access Protocol\n"); break; 
    case 96: printf("REMOVED/Unassigned\n"); break; 
    case 97: printf("UUID/GUID - UUID/GUID-based Client Identifier\n"); break; 
    case 98: printf("User-Auth - Open Group's User Authentication\n"); break; 
    case 99: printf("GEOCONF_CIVIC\n"); break; 
    case 100: printf("PCode - IEEE 1003.1 TZ String\n"); break; 
    case 101: printf("REMOVED/Unassigned\n"); break; 
    case 102: printf("REMOVED/Unassigned\n"); break; 
    case 103: printf("REMOVED/Unassigned\n"); break; 
    case 104: printf("REMOVED/Unassigned\n"); break; 
    case 105: printf("REMOVED/Unassigned\n"); break; 
    case 106: printf("REMOVED/Unassigned\n"); break; 
    case 107: printf("REMOVED/Unassigned\n"); break; 
    case 108: printf("IPv6-Only Preferred - Number of seconds that DHCPv4 should be disabled\n"); break; 
    case 109: printf("OPTION_DHCP4O6_S46_SADDR - DHCPv4 over DHCPv6 Softwire Source Address Option\n"); break; 
    case 110: printf("REMOVED/Unassigned\n"); break; 
    case 111: printf("Unassigned\n"); break; 
    case 112: printf("Netinfo Address - NetInfo Parent Server Address\n"); break; 
    case 113: printf("Netinfo Tag - NetInfo Parent Server Tag\n"); break; 
    case 114: printf("DHCP Captive-Portal - DHCP Captive-Portal\n"); break; 
    case 115: printf("REMOVED/Unassigned\n"); break; 
    case 116: printf("Auto-Config - DHCP Auto-Configuration\n"); break; 
    case 117: printf("Name Service Search - Name Service Search\n"); break; 
    case 118: printf("Subnet Selection Option - Subnet Selection Option\n"); break; 
    case 119: printf("Domain Search - DNS domain search list\n"); break; 
    case 120: printf("SIP Servers DHCP Option - SIP Servers DHCP Option\n"); break; 
    case 121: printf("Classless Static Route Option - Classless Static Route Option\n"); break; 
    case 122: printf("CCC - CableLabs Client Configuration\n"); break; 
    case 123: printf("GeoConf Option - GeoConf Option\n"); break; 
    case 124: printf("V-I Vendor Class - Vendor-Identifying Vendor Class\n"); break; 
    case 125: printf("V-I Vendor-Specific Information - Vendor-Identifying Vendor-Specific Information\n"); break; 
    case 126: printf("REMOVED/Unassigned\n"); break; 
    case 127: printf("REMOVED/Unassigned\n"); break; 
    case 128: printf("PXE - undefined (vendor specific) - Etherboot signature. 6 bytes: E4:45:74:68:00:00 - DOCSIS \"full security\" server IP address - TFTP Server IP address (for IP Phone software load)\n"); break; 
    case 129: printf("PXE - undefined (vendor specific) - Kernel options. Variable length string - Call Server IP address\n"); break; 
    case 130: printf("PXE - undefined (vendor specific) - Ethernet interface. Variable length string. - Discrimination string (to identify vendor)\n"); break; 
    case 131: printf("PXE - undefined (vendor specific) - Remote statistics server IP address\n"); break; 
    case 132: printf("PXE - undefined (vendor specific) - IEEE 802.1Q VLAN ID\n"); break; 
    case 133: printf("PXE - undefined (vendor specific) - IEEE 802.1D/p Layer 2 Priority\n"); break; 
    case 134: printf("PXE - undefined (vendor specific) - Diffserv Code Point (DSCP) for VoIP signalling and media streams\n"); break; 
    case 135: printf("PXE - undefined (vendor specific) - HTTP Proxy for phone-specific applications\n"); break; 
    case 136: printf("OPTION_PANA_AGENT\n"); break; 
    case 137: printf("OPTION_V4_LOST\n"); break; 
    case 138: printf("OPTION_CAPWAP_AC_V4 - CAPWAP Access Controller addresses\n"); break; 
    case 139: printf("OPTION-IPv4_Address-MoS - a series of suboptions\n"); break; 
    case 140: printf("OPTION-IPv4_FQDN-MoS - a series of suboptions\n"); break; 
    case 141: printf("SIP UA Configuration Service Domains - List of domain names to search for SIP User Agent Configuration\n"); break; 
    case 142: printf("GeoLoc - Geospatial Location Configuration Information\n"); break; 
    case 143: printf("FORCERENEW_NONCE_CAPABLE\n"); break; 
    case 144: printf("REMOVED/Unassigned\n"); break; 
    case 145: printf("REMOVED/Unassigned\n"); break; 
    case 146: printf("V-I Vendor Class - Vendor Class to be injected in DHCP Requests\n"); break; 
    case 147: printf("V-I Vendor-Specific Information - Vendor Specific Information to be injected in DHCP Requests\n"); break; 
    case 148: printf("TFTP server address\n"); break; 
    case 149: printf("Call Server address\n"); break; 
    case 150: printf("Discrimination string\n"); break; 
    case 151: printf("Remote statistics server address\n"); break; 
    case 152: printf("IEEE 802.1Q VLAN ID\n"); break; 
    case 153: printf("IEEE 802.1D/p Layer 2 Priority\n"); break; 
    case 154: printf("Diffserv Code Point (DSCP) for VoIP signaling and media streams\n"); break; 
    case 155: printf("HTTP Proxy for phone-specific applications\n"); break; 
    case 156: printf("PANA Authentication Agent\n"); break; 
    case 157: printf("LoST server\n"); break; 
    case 158: printf("CAPWAP Access Controller addresses\n"); break; 
    case 159: printf("IPv4 Address MoS - a series of suboptions\n"); break; 
    case 160: printf("IPv4 FQDN MoS - a series of suboptions\n"); break; 
    case 161: printf("SIP UA Configuration Service Domains - List of domain names to search for SIP User Agent Configuration\n"); break; 
    case 162: printf("OPTION-IPv4_Address-ANDSF\n"); break; 
    case 163: printf("OPTION-IPv6_Address-ANDSF\n"); break; 
    case 164: printf("GeoLoc\n"); break; 
    case 165: printf("FORCERENEW_NONCE_CAPABLE\n"); break; 
    case 166: printf("REMOVED/Unassigned\n"); break; 
    case 167: printf("REMOVED/Unassigned\n"); break; 
    case 168: printf("V-I Vendor Class - Vendor Class to be injected in DHCP Requests\n"); break; 
    case 169: printf("V-I Vendor-Specific Information - Vendor Specific Information to be injected in DHCP Requests\n"); break; 
    case 170: printf("TFTP server address\n"); break; 
    case 171: printf("Call Server address\n"); break; 
    case 172: printf("Discrimination string\n"); break; 
    case 173: printf("Remote statistics server address\n"); break; 
    case 174: printf("IEEE 802.1Q VLAN ID\n"); break; 
    case 175: printf("IEEE 802.1D/p Layer 2 Priority\n"); break; 
    case 176: printf("Diffserv Code Point (DSCP) for VoIP signaling and media streams\n"); break; 
    case 177: printf("HTTP Proxy for phone-specific applications\n"); break; 
    case 178: printf("PANA Authentication Agent\n"); break; 
    case 179: printf("LoST server\n"); break; 
    case 180: printf("CAPWAP Access Controller addresses\n"); break; 
    case 181: printf("IPv4 Address MoS - a series of suboptions\n"); break; 
    case 182: printf("IPv4 FQDN MoS - a series of suboptions\n"); break; 
    case 183: printf("SIP UA Configuration Service Domains - List of domain names to search for SIP User Agent Configuration\n"); break; 
    case 184: printf("OPTION-IPv4_Address-ANDSF\n"); break; 
    case 185: printf("OPTION-IPv6_Address-ANDSF\n"); break; 
    case 186: printf("GeoLoc\n"); break; 
    case 187: printf("FORCERENEW_NONCE_CAPABLE\n"); break; 
    case 188: printf("REMOVED/Unassigned\n"); break; 
    case 189: printf("REMOVED/Unassigned\n"); break; 
    case 190: printf("V-I Vendor Class - Vendor Class to be injected in DHCP Requests\n"); break; 
    case 191: printf("V-I Vendor-Specific Information - Vendor Specific Information to be injected in DHCP Requests\n"); break; 
    case 192: printf("TFTP server address\n"); break; 
    case 193: printf("Call Server address\n"); break; 
    case 194: printf("Discrimination string\n"); break; 
    case 195: printf("Remote statistics server address\n"); break; 
    case 196: printf("IEEE 802.1Q VLAN ID\n"); break; 
    case 197: printf("IEEE 802.1D/p Layer 2 Priority\n"); break; 
    case 198: printf("Diffserv Code Point (DSCP) for VoIP signaling and media streams\n"); break; 
    case 199: printf("HTTP Proxy for phone-specific applications\n"); break; 
    case 200: printf("PANA Authentication Agent\n"); break; 
    case 201: printf("LoST server\n"); break; 
    case 202: printf("CAPWAP Access Controller addresses\n"); break; 
    case 203: printf("IPv4 Address MoS - a series of suboptions\n"); break; 
    case 204: printf("IPv4 FQDN MoS - a series of suboptions\n"); break; 
    case 205: printf("SIP UA Configuration Service Domains - List of domain names to search for SIP User Agent Configuration\n"); break; 
    case 206: printf("OPTION-IPv4_Address-ANDSF\n"); break; 
    case 207: printf("OPTION-IPv6_Address-ANDSF\n"); break; 
    case 208: printf("GeoLoc\n"); break; 
    case 209: printf("FORCERENEW_NONCE_CAPABLE\n"); break; 
    case 210: printf("REMOVED/Unassigned\n"); break; 
    case 211: printf("REMOVED/Unassigned\n"); break; 
    case 212: printf("V-I Vendor Class - Vendor Class to be injected in DHCP Requests\n"); break; 
    case 213: printf("V-I Vendor-Specific Information - Vendor Specific Information to be injected in DHCP Requests\n"); break; 
    case 214: printf("TFTP server address\n"); break; 
    case 215: printf("Call Server address\n"); break; 
    case 216: printf("Discrimination string\n"); break; 
    case 217: printf("Remote statistics server address\n"); break; 
    case 218: printf("IEEE 802.1Q VLAN ID\n"); break; 
    case 219: printf("IEEE 802.1D/p Layer 2 Priority\n"); break; 
    case 220: printf("Diffserv Code Point (DSCP) for VoIP signaling and media streams\n"); break; 
    case 221: printf("HTTP Proxy for phone-specific applications\n"); break; 
    case 222: printf("PANA Authentication Agent\n"); break; 
    case 223: printf("LoST server\n"); break; 
    case 224: printf("CAPWAP Access Controller addresses\n"); break; 
    case 225: printf("IPv4 Address MoS - a series of suboptions\n"); break; 
    case 226: printf("IPv4 FQDN MoS - a series of suboptions\n"); break; 
    case 227: printf("SIP UA Configuration Service Domains - List of domain names to search for SIP User Agent Configuration\n"); break; 
    case 228: printf("OPTION-IPv4_Address-ANDSF\n"); break; 
    case 229: printf("OPTION-IPv6_Address-ANDSF\n"); break; 
    case 230: printf("GeoLoc\n"); break; 
    case 231: printf("FORCERENEW_NONCE_CAPABLE\n"); break; 
    case 232: printf("REMOVED/Unassigned\n"); break; 
    case 233: printf("REMOVED/Unassigned\n"); break; 
    case 234: printf("V-I Vendor Class - Vendor Class to be injected in DHCP Requests\n"); break; 
    case 235: printf("V-I Vendor-Specific Information - Vendor Specific Information to be injected in DHCP Requests\n"); break; 
    case 236: printf("TFTP server address\n"); break; 
    case 237: printf("Call Server address\n"); break; 
    case 238: printf("Discrimination string\n"); break; 
    case 239: printf("Remote statistics server address\n"); break; 
    case 240: printf("IEEE 802.1Q VLAN ID\n"); break; 
    case 241: printf("IEEE 802.1D/p Layer 2 Priority\n"); break; 
    case 242: printf("Diffserv Code Point (DSCP) for VoIP signaling and media streams\n"); break; 
    case 243: printf("HTTP Proxy for phone-specific applications\n"); break; 
    case 244: printf("PANA Authentication Agent\n"); break; 
    case 245: printf("LoST server\n"); break; 
    case 246: printf("CAPWAP Access Controller addresses\n"); break; 
    case 247: printf("IPv4 Address MoS - a series of suboptions\n"); break; 
    case 248: printf("IPv4 FQDN MoS - a series of suboptions\n"); break; 
    case 249: printf("SIP UA Configuration Service Domains - List of domain names to search for SIP User Agent Configuration\n"); break; 
    case 250: printf("OPTION-IPv4_Address-ANDSF\n"); break; 
    case 251: printf("OPTION-IPv6_Address-ANDSF\n"); break; 
    case 252: printf("GeoLoc\n"); break; 
    case 253: printf("FORCERENEW_NONCE_CAPABLE\n"); break; 
    case 254: printf("Unassigned\n"); break; 
    case 255: printf("End of Options List\n"); break; 
    default: printf("Unknown DHCP Option Code\n");
    }
}



/*char* genIp(int bitMask, char* subCIDR) {
    //printf("made it");
    PGconn *conn = PQconnectdb("host=localhost dbname=dhcp user=grant password=bowieboom123");
    printf("made it");
    int len = 255;
    char temp[3];
    char *res[32];
    strcpy(*res, subCIDR);

    if (bitMask == 24) {
        for (int i = 1; i < len - 2; i++) {
            sprintf(temp, "%d", i);
            
            strcat(*res, temp);

            if (!ipLeased(conn, *res)) {
                return *res;
            }
        }
    }  
    return *res; 
}*/
 
