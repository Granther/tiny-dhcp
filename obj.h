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

#ifndef OBJ_H
    #define OBJ_H

    #define SERVER_PORT 67
    #define CLIENT_PORT 68

    #define DHCP_DISCOVER 1
    #define DHCP_OFFER 2
    #define DHCP_REQUEST 3
    #define DHCP_ACK 5

    #define DHCP_OP_MESSGAGE_HEX 0x35
    #define DISCOVER_HEX 0x01
    #define OFFER_HEX 0x02
    #define REQUEST_HEX 0x03
    #define ACK_HEX 0x05

    #define GLOBAL_OPTIONS_LEN 214

    // --- HEXS' --- //
    #define RENEWAL_TIME_HEX 0x3A
    #define REBINDING_TIME_HEX 0x3B
    #define IP_ADDR_LEASE_TIME_HEX 0x33
    #define DOMAIN_NAME_HEX 0x0F
    #define TIME_OFFSET_HEX 0x02
    #define ROUTER_HEX 0x03
    #define SUBNET_HEX 0x01
    #define TIME_SERVER_HEX 0x04
    #define REQUEST_LIST_HEX 0x37
    #define MAX_SIZE_HEX 0x39
    #define SUBNET_MASK_HEX 0x01
    #define SERVER_IDENT_HEX 0x36
    #define CLIENT_IDENT_HEX 0x3D 
    #define DNS_HEX 0x06
    #define REQ_IP_HEX 0x32


    // --- VALUE LENGTHS --- //
    #define ROUTER_LEN 0x04
    #define MAX_SIZE_LEN 0x02
    #define MAGIC_COOKIE_LEN 0x04
    #define IP_LEASE_TIME_LEN 0x04
    #define REBINDING_TIME_LEN 0x04
    #define RENEWAL_TIME_LEN 0x04
    #define DOMAIN_NAME_LEN 0x0C
    #define SUBNET_MASK_LEN 0x04
    #define SERVER_IDENT_LEN 0x04
    #define DNS_LEN 0x04
    #define IP_LEN 0x04;

    #define SIZE 256;

    typedef struct DhcpPacket { 
        uint8_t op;            // Operation Code
        uint8_t htype;         // Hardware Type
        uint8_t hlen;          // Hardware Address Length
        uint8_t hops;          // Hops
        uint32_t xid;          // Transaction ID
        uint16_t secs;         // Seconds
        uint16_t flags;        // Flags
        uint32_t ciaddr;       // Client IP Address
        uint32_t yiaddr;       // Your IP Address
        uint32_t siaddr;       // Server IP Address
        uint32_t giaddr;       // Gateway IP Address
        uint8_t chaddr[16];    // Client Hardware Address
        uint8_t sname[64];     // Server Name
        uint8_t file[128];     // Boot File Name
        uint8_t options[214];  // DHCP Options (adjust size as needed)

        uint8_t opCodes[16];
        uint8_t opCodeIndexes[16];
    } DhcpPacket;

    typedef struct LeasedClient {
        char* leased_ip;
        char* chaddr;
        uint32_t renewal_time;
        uint32_t rebinding_time;
        uint32_t lease_length;
    } LeasedClient;

    typedef struct {
        char* database_name;
        char* leases_name;
        char* user_name;
        char* password;
        char* host;
        bool archive_duplicates;
        char* dns;
        char* router;
        char* subnet;
        char* interface;
    } Settings;
#endif   






