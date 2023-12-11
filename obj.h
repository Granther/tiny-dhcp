#include "included.h"

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
    #define DECLINE_HEX 0x04
    #define ACK_HEX 0x05
    #define NAK_HEX 0x06
    #define RELEASE_HEX 0x07
    #define INFORM_HEX 0x08

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
    #define CLIENT_IDENT_LEN 0x6
    #define IP_ADDR_LEASE_TIME_LEN 0x4
    #define TIME_OFFSET_LEN 0x4
    #define SERVER_NAME_HEX 0x40

    #define TERMINAL_MODE 0
    #define SERVICE_MODE 1

    typedef struct {
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
        int mode;
    } Settings;

#endif   






