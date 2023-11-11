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

#define SIZE 256

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
