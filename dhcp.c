#ifndef INCLUDED_H
    #include "included.h"
#endif

#ifndef OBJ_H
    #include "obj.h"
#endif
    
#ifndef DUO_NODE_H
    #include "duo_node.h"
#endif

#ifndef SQL_H
    #include "sql.h"
#endif

#ifndef SETTINGS_H
    #include "settings.h"
#endif

#ifndef DHCPPACKET_H
    #include "dhcppacket.h"
#endif

#ifndef UTILITY_H
    #include "utility.h"
#endif

// --- GLOBAL DHCP SETTINGS --- //
uint8_t RENEWAL_TIME_VAL [16] = {0x00, 0x00, 0x38, 0x40}; // 4 hours
uint8_t REBINDING_TIME_VAL [16] = {0x00, 0x01, 0x62, 0x70}; //7 hours
uint8_t IP_ADDR_LEASE_TIME_VAL [16] = {0x00, 0x00, 0x70, 0x80};//8 hours 

uint32_t IP_ADDR_LEASE_TIME_VAL_32 = {0x00007080}; 
uint32_t REBINDING_TIME_VAL_32 = {0x00016270};
uint32_t RENEWAL_TIME_VAL_32 = {0x00003840};

uint8_t DOMAIN_NAME_VAL [16] = {0x61, 0x74, 0x74, 0x6c, 0x6f, 0x63, 0x61, 0x6c, 0x2e, 0x6e, 0x65, 0x74};
uint8_t TIME_OFFSET_VAL [16] = {0xFF, 0xFF, 0xC7, 0xC0};

uint8_t MAGIC_COOKIE_VAL [16] = {0x63, 0x82, 0x53, 0x63};
uint8_t MAX_SIZE_VAL [16] = {0x05, 0xDC};
uint8_t SERVER_IDENT_VAL [16] = {0x0A, 0x0A, 0x3D, 0x2C};

uint8_t SERVER_NAME_VAL [64] = {0x67, 0x6c, 0x6f, 0x72, 0x70, 0x74, 0x6f, 0x77, 0x6e};

// --- GLOBAL SETTING OPERATION VALUES --- //

#define BROADCAST_ADDR 0xFFFFFFFF

int opInd = 0;
uint8_t optionArr[GLOBAL_OPTIONS_LEN];
    
// --- ARG PARSER --- //
int readOptions(DhcpPacket *pack, int sock);
void info();
void parser(int argc, char *argv[]);
void dealFlag(char* flag, char* argList[256]);
bool flagEquals(char* flag, char* x, char* y, char* z);
bool isFlag(int argc, char *argv[], int i);
bool isNullArg(int argc, char *argv[], int i);

// --- MAIN DHCP --- //
int dhcpMain(int mode);
int sendOffer(DhcpPacket *discPack);
int sendAck(DhcpPacket *reqPack);
void lease(char* hard_addr, char* str);
int loadStuff();
int getGateway(char* gate);
int getMaskNum();
char* genIp(int bitMask, char* subCIDR);
long howManyIps(int bitMask);

int validateInterface(char* interface);

void endOpsCombine(DhcpPacket *pack);
void clearOptionArr();

// --- PACKET --- //
bool hasMagic(uint8_t op[GLOBAL_OPTIONS_LEN]);
int parseOptions(DhcpPacket *reqPack, DhcpPacket *ansPack);
uint8_t* readData(DhcpPacket *pack, int ind);
void writeData(uint8_t opCode, uint8_t len, uint8_t vals[16]);
int writeCookie();
char* getOp(DhcpPacket dp, int opInd, int opLen);
void handleReq(DhcpPacket *pack);
int getFromOptions(uint8_t options[GLOBAL_OPTIONS_LEN], uint8_t opCode, uint8_t* list);
void setXid(DhcpPacket *pack, uint32_t olXid);
void boilerOffer(DhcpPacket *offPack, DhcpPacket *discPack);
void endOpsCombine(DhcpPacket *pack);
void boilerAck(DhcpPacket *ackPack, DhcpPacket *reqPack);

bool opCodeExists(DhcpPacket* pack, uint8_t opCode);
int getFromOptionsRedux(DhcpPacket* pack, uint8_t opCode, uint8_t* retList);
int getOpLen(DhcpPacket* pack, uint8_t opCode);

int getMacFromIdent(uint8_t* ident, uint8_t* mac);
int getSubnetFromMask();
int getCurrentInterface(char* interfaceGlob);
bool isCorrectMask(uint32_t addr);

int optionsToStruct(DhcpPacket *pack);

int sendNak(DhcpPacket* reqPack, int sock);
int file_desc_test(char *test);

// --- SETTING STUFF --- //
void daemonize();
void opReader(size_t opCode);

int createRoleModel();
int get_sockfd();

int getDNS();

#define BIGGY_ENDIAN 0
#define LITTLEY_ENDIAN 1 
#define IP_TO_HEX 0
#define HEX_TO_IP 1

int main(int argc, char *argv[]) 
{    

	if (argc == 1) 
	{
		info();
	}
	if (argc > 1)
	{	
		parser(argc, argv); 
	}
    return 0;
}

int get_sockfd() {
    char **names = NULL;
    int num_fds;
    int sockfd;

    sockfd = -1;
    num_fds = sd_listen_fds_with_names(0, &names);
    if (num_fds < 0) {
        perror("sd_listen_fds_with_names");
        return 1;
    }

    if (num_fds == 0 || names == NULL) {
        fprintf(stderr, SD_WARNING "Unable to find FD\n");
        return -1;
    }

    fprintf(stderr, SD_NOTICE "FD Names are: \n");

    for (int i = 0; i < num_fds; i++) {
        fprintf(stderr, SD_NOTICE " %s\n", names[i]);

        if (sd_is_socket_unix(i+SD_LISTEN_FDS_START, -1, SOCK_DGRAM, (const char*)names[i], strlen(names[i])));
            sockfd = i+SD_LISTEN_FDS_START;
    }

    free(names);

    return sockfd;
}

int file_desc_test(char *test) {
    int sockfd; // we will get this from systemd and it will be foo.socket
    struct sockaddr_un client; // unix domain socket client address
    socklen_t addrlen;
    ssize_t num_bytes; // bytes received from the socket
    char buf[1024]; // buffer to receive from socket

    fprintf(stderr, SD_NOTICE "foo service started\n");

    sockfd = get_sockfd();
    if(sockfd == -1)
    {
        fprintf(stdout, SD_ERR "Unable to get file descriptor for socket\n");
        sd_notify(0, "STOPPING=1");
        return -1;
    }

    // tell the service manager we're in the ready state
    sd_notify(0, "READY=1");
    while(1)
    {
        num_bytes = recvfrom(sockfd, buf, 1024, 0, (struct sockaddr*) &client, &addrlen);
        if(num_bytes == -1)
        {
        perror("error receiving from unix domain socket");
        continue;
        }
        buf[num_bytes] = '\0';
        fprintf(stderr, SD_NOTICE "Received %ld bytes from %s: %s\n", num_bytes, client.sun_path, buf);
    }

    return 0;
}

int dhcpMain(int mode) 
{
    options_hr_t *ops = (options_hr_t*)malloc(sizeof(options_hr_t));

    clearOptionArr();
    
    loadStuff();

    int sock;

    struct sockaddr_in server_addr, client_addr;

    if (mode == TERMINAL_MODE) {
        sock = socket(AF_INET, SOCK_DGRAM, 0); // Ipv4, UDP, Default protocol for SOCK_DGRAM 
    }
    else if (mode == SERVICE_MODE) {
        sock = get_sockfd();
    }

    if (sock == -1) {
        fprintf(stdout, SD_ERR "Unable to get file descriptor for socket\n");
        sd_notify(0, "STOPPING=1");
        return -1;
    }
     
    memset(&server_addr, 0, sizeof(server_addr)); // Var in mem, what to write to block, size of block. Makes it NULL
    //Set up and bind socket

    server_addr.sin_family = AF_INET; // Makes the address type used IPv4
    server_addr.sin_addr.s_addr = htonl(INADDR_ANY); // Sets the ip to accept connections on any of its interfaces. htonl converts from host byte to network byte
    server_addr.sin_port = htons(SERVER_PORT); // Sets the value to port 67 (DHCP Server port)

    bind(sock, (struct sockaddr*)&server_addr, sizeof(server_addr)); // Binds socket to serveraddr

    //sd_notify(0, "READY=1"); // Notify systemd that we are READY

    while(1) {
        socklen_t len = sizeof(client_addr); // Stores size of client address
        char buf[1024]; // Recieved data buffer 
        memset(buf, 0, sizeof(buf)); // Clears the entire buffer, sets to 0
        recvfrom(sock, buf, sizeof(buf), 0, (struct sockaddr*)&client_addr, &len);
        // (the socket, where to buffer, buffer size, 0, changes server_addr ro pointer, store size of client addr)

        vanilla_dhcp_t *vdhcp_pack = (vanilla_dhcp_t*)buf; // Cast the buffer to a DHCP packet structure (assuming you have defined the structure)
        init_vanilla_dhcp(vdhcp_pack);

        if (dhcpPacket->op != 0) {
            //close(sock);

            dhcppacket_all_hr *hr = (dhcppacket_all_hr*)malloc(sizeof(dhcppacket_all_hr));

            netToHr(dhcpPacket, hr);

            readout_hr_pack(hr);

            //readOptions(dhcpPacket, sock);

            free(hr);

            return EXIT_SUCCESS;
        }
    }
    close(sock);
    return EXIT_SUCCESS;
}

int optionsToStruct(DhcpPacket *pack) {

    getFromOptionsRedux(pack, CLIENT_IDENT_HEX, pack->ops->client_id);
    getFromOptionsRedux(pack, SERVER_IDENT_HEX, pack->ops->server_id);
    getFromOptionsRedux(pack, RENEWAL_TIME_HEX, pack->ops->renewal_time);
    getFromOptionsRedux(pack, REBINDING_TIME_HEX, pack->ops->rebinding_time);
    getFromOptionsRedux(pack, IP_ADDR_LEASE_TIME_HEX, pack->ops->ip_lease_length);
    getFromOptionsRedux(pack, DOMAIN_NAME_HEX, pack->ops->domain_name);
    getFromOptionsRedux(pack, TIME_OFFSET_HEX, pack->ops->time_offset);
    getFromOptionsRedux(pack, MAX_SIZE_HEX, pack->ops->max_size);

    return 0;
}

bool decider(DhcpPacket *pack, int intention) {

    //options_t *ops = (options_t*)malloc(sizeof(options_t)); optionsToStruct(pack, ops); 

    // What will kill a connection

    /* DISCOVER
        
    */

    switch (intention) {
        case DHCP_OFFER:

            break;
        case DHCP_ACK:

            break;
    }
}

// Get connection
// Try too handle connection
// Add the conn to a queue that removes processes based on TTL
// Decide what we want to do with that conn using the data we have
    // We may decide to DROP
    // Or to continue
// We can examine past but valid conns in out conn queue
    // Reasons to drop DISCOVER
        // We see another DHCP OFFER in the queue
        // That client is not allowed to ask for an address
        // The client isnt asking us
    // Reasons to drop a REQUEST
        // Another DHCP server sends a valid ACK before we can
        // That client isnt asking us 
        // The clientis not allowed 

int sendOffer(DhcpPacket *discPack) 
{// Recieved data buffer 

    //loadStuff();

    clearOptionArr(); // Clear global options array

    leapFrogOps(discPack);

    uint8_t ipU8[getOpLen(discPack, 0x32)];
    uint8_t clIdent[getOpLen(discPack, 0x3D)];

    getFromOptionsRedux(discPack, 0x32, ipU8);
    getFromOptionsRedux(discPack, 0x3D, clIdent);

    char* ipStr = (char*)malloc(32);

    uint32_t ipU32 = u8ToU32(ipU8);

    bool check = isCorrectMask(ipU32);

    if (check)
    {
        printf("%x Is the CORRECT mask\n", ipU32);
    }
    else if (!check)
    {
        printf("%x Is NOT the correct mask\n", ipU32);
        getUnleasedIp(ipStr, getMaskNum()); 
        ipStrToU8(ipStr, ipU8);
    }

    DhcpPacket offPack; // Create packet to write offer to

    memset(&offPack, 0, sizeof(offPack)); // Clear the packet

    boilerOffer(&offPack, discPack); // Write some boiler plate/default options to the packet

    setXid(&offPack, discPack->xid); // Set the session ID to that of the Discover packet

    int bitMask = getMaskNum(); 

    //offPack.yiaddr = eightTo32(getFromOptions(discPack->options, 0x32, 0x04));
    offPack.yiaddr = ipU32;
    offPack.siaddr = u8ToU32(serverIdent);
    //printf("8to32: %u\n", serverIdent);

    for (int i = 0; i < sizeof(discPack->chaddr); i++) {
        offPack.chaddr[i] = discPack->chaddr[i];
    }
    
    writeCookie(); // Write Magic Cookie to offer packet
    
    handleReq(discPack); // Handle the reqest list from the Discover packet

    int sockfd = socket(AF_INET, SOCK_DGRAM, 0);

    if (sockfd == -1) {
        perror("socket");
        exit(EXIT_FAILURE);
        return 1;
    }

    int broadcastEnable = 1;

    if (setsockopt(sockfd, SOL_SOCKET, SO_BROADCAST, &broadcastEnable, sizeof(broadcastEnable)) == -1) {
        perror("setsockopt (SO_BROADCAST)");
        close(sockfd);
        return 1;
    }

    struct sockaddr_in client_addr;
    memset(&client_addr, 0, sizeof(client_addr));

    uint8_t offer[16] = {OFFER_HEX};
    uint8_t max_size[16] = {0x05, 0xDC};
    uint8_t clIdent16[32];

    uint8_t *clientIdent = (uint8_t*)malloc(32); getFromOptions(discPack->options, 0x3D, clientIdent);

    writeData(DHCP_OP_MESSGAGE_HEX, 0x01, offer);
    writeData(0x32, 0x04, ipU8);
    writeData(CLIENT_IDENT_HEX, 0x07, clientIdent);
    writeData(SERVER_IDENT_HEX, 0x04, serverIdent);
    writeData(TIME_OFFSET_HEX, 0x04, TIME_OFFSET_VAL);
    writeData(REBINDING_TIME_HEX, 0x04, REBINDING_TIME_VAL);
    writeData(RENEWAL_TIME_HEX, 0x04, RENEWAL_TIME_VAL);
    writeData(IP_ADDR_LEASE_TIME_HEX, 0x04, IP_ADDR_LEASE_TIME_VAL);
    writeData(0x39, 0x02, max_size);

    endOpsCombine(&offPack); 


    uint32_t u = BROADCAST_ADDR;

    struct sockaddr_in src_addr, dest_addr;
    memset(&src_addr, 0, sizeof(src_addr));
    memset(&dest_addr, 0, sizeof(dest_addr));

    src_addr.sin_family = AF_INET;
    src_addr.sin_addr.s_addr = htonl(INADDR_ANY);
    src_addr.sin_port = htons(67);

    dest_addr.sin_family = AF_INET;
    dest_addr.sin_port = htons(68);
    dest_addr.sin_addr.s_addr = htonl(u);

    if (bind(sockfd, (struct sockaddr*)&src_addr, sizeof(src_addr)) == -1) {
        perror("offer bind");
        close(sockfd);
    }

    for (int i = 0; i < sizeof(optionArr); i++) {
        offPack.options[i] = optionArr[i];
    }
    ssize_t sentBytes = sendto(sockfd, &offPack, sizeof(offPack), 0, (struct sockaddr*)&dest_addr, sizeof(dest_addr));

    if (sentBytes == -1) {
        perror("sendto");
        close(sockfd);
    }

    close(sockfd);
    printf("\n----- SENT OFFER -----\n\n\n");
    free(ipStr);
    return 0;
}

bool opCodeExists(DhcpPacket* pack, uint8_t opCode) 
{
    /*for (size_t i = 0; i < sizeof(pack->options); i++)
    {
        if (pack->options[i] == opCode)
        {
            return true;
        }
    }*/

    leapFrogOps(pack);

    for (int i = 0; i < sizeof(pack->opCodes); i++) {
        if (pack->opCodes[i] == opCode) {
            return true;
        }
    }

    return false;
}

int
createRoleModel ()
{
    uint32_t goop = htonl(u8ToU32(router));

    roleModel = goop >> (32 - getMaskNum());
}

bool
isCorrectMask(uint32_t addr)
{
    int mask = getMaskNum();
    addr = htonl(addr) >> (32 - mask);
    
    uint32_t test = roleModel | addr;

    if (test == roleModel)
    {
        return true;
    }
    else if (test != roleModel)
    {
        return false;
    }
}

int getFromOptionsRedux(DhcpPacket* pack, uint8_t opCode, uint8_t* retList) 
{
    int opCodeInd = 0;
    int opCodeValLen = 0; 
    int p = 0;

    for (size_t i = 0; i < sizeof(pack->opCodes); i++) 
    {
        if (!opCodeExists(pack, opCode))
        {
            for (int i = 0; i < sizeof(retList); i++) {
                retList[i] = 0x11;
            }
        }

        if (pack->opCodes[i] == opCode)
        {
            opCodeInd = getAtIndex(pack->opCodeIndexes, i);
            //printf("opcodeind: %d\n", opCodeInd);
            opCodeValLen = pack->options[opCodeInd + 1]; 
            //printf("opcodevallen: %d\n", opCodeValLen);
            break;
        }
    }

    for (size_t i = opCodeInd + 2; i < opCodeInd + opCodeValLen + 2; i++) 
    {
        retList[p] = pack->options[i];
        p++;
    }

    return 0;
}

int 
sendAck(DhcpPacket *reqPack) 
{ 
    DhcpPacket ackPack; 

    LeasedClient lc; LeasedClient* lcPtr;

    leapFrogOps(reqPack);

    uint8_t ipU8[getOpLen(reqPack, 0x32)];
    uint8_t clIdent[getOpLen(reqPack, 0x3D)];

    getFromOptionsRedux(reqPack, 0x32, ipU8);

    char* ipStr = (char*)malloc(32);

    uint32_t ipU32 = u8ToU32(ipU8);

    bool check = isCorrectMask(ipU32);

    // If is the correct mask, and addr is not leased, lease. 
    // If is the correct mask, and addr is leased, check if mac has lease, offer that addr, if they dont accept, remove


    if (check) 
    {
        printf("%x Is the CORRECT mask\n", ipU32);
        u8ToIpStr(ipU8, ipStr);
    }
    else if (!check)
    {
        printf("%x Is NOT the correct mask\n", ipU32);
        getUnleasedIp(ipStr, getMaskNum()); 
        ipStrToU8(ipStr, ipU8);
    }

    getFromOptionsRedux(reqPack, 0x3D, clIdent);

    char macStr[30]; u8ToMacStr(reqPack->chaddr, macStr);

    lc.leased_ip = ipStr; lc.chaddr = macStr;
    lc.lease_length = IP_ADDR_LEASE_TIME_VAL_32; 
    lc.rebinding_time = REBINDING_TIME_VAL_32;
    lc.renewal_time = RENEWAL_TIME_VAL_32;

    //printf("macstr: %s\n", macStr);

    if (checkIfMacHasLease(macStr))
    {
        printf("glorp\n");
    }

    printf("ip: %s\n", lc.leased_ip);

    lcPtr = &lc;

    leaseToDB(lcPtr);

    memset(&ackPack, 0, sizeof(ackPack));

    boilerAck(&ackPack, reqPack);

    setXid(&ackPack, reqPack->xid);

    ackPack.yiaddr = ipU32;
    ackPack.siaddr = u8ToU32(serverIdent);

    for (int i = 0; i < sizeof(reqPack->chaddr); i++) {
        ackPack.chaddr[i] = reqPack->chaddr[i];
    }
    
    writeCookie();

    uint8_t ack[16] = {ACK_HEX};
    uint8_t max_size[16] = {0x05, 0xDC};

    writeData(DHCP_OP_MESSGAGE_HEX, 0x01, ack);
    writeData(CLIENT_IDENT_HEX, getOpLen(reqPack,0x3D), clIdent);
    writeData(0x32, getOpLen(reqPack, 0x32), ipU8);
    writeData(SERVER_IDENT_HEX, 0x04, serverIdent);
    writeData(TIME_OFFSET_HEX, 0x04, TIME_OFFSET_VAL);
    writeData(REBINDING_TIME_HEX, 0x04, REBINDING_TIME_VAL);
    writeData(RENEWAL_TIME_HEX, 0x04, RENEWAL_TIME_VAL);
    writeData(IP_ADDR_LEASE_TIME_HEX, 0x04, IP_ADDR_LEASE_TIME_VAL);
    writeData(0x39, 0x02, max_size);


    handleReq(reqPack);

    endOpsCombine(&ackPack);

    for (int i = 0; i < sizeof(reqPack->chaddr); i++) {
        ackPack.chaddr[i] = reqPack->chaddr[i];
    }
    
    int sockfd = socket(AF_INET, SOCK_DGRAM, 0);

    if (sockfd == -1) {
        perror("socket");
        exit(EXIT_FAILURE);
    }

    int broadcastEnable = 1;

    if (setsockopt(sockfd, SOL_SOCKET, SO_BROADCAST, &broadcastEnable, sizeof(broadcastEnable)) == -1) {
        perror("setsockopt (SO_BROADCAST)");
        close(sockfd);
    }

    uint32_t u = 0xffffffff;

    struct sockaddr_in src_addr, dest_addr;
    memset(&src_addr, 0, sizeof(src_addr));
    memset(&dest_addr, 0, sizeof(dest_addr));

    src_addr.sin_family = AF_INET;
    src_addr.sin_addr.s_addr = htonl(INADDR_ANY);
    src_addr.sin_port = htons(67);

    dest_addr.sin_family = AF_INET;
    dest_addr.sin_port = htons(68);
    dest_addr.sin_addr.s_addr = htonl(u);

    if (bind(sockfd, (struct sockaddr*)&src_addr, sizeof(src_addr)) == -1) {
        perror("offer bind");
        close(sockfd);
    }

    for (int i = 0; i < sizeof(optionArr); i++) {
        ackPack.options[i] = optionArr[i];
    }
    ssize_t sentBytes = sendto(sockfd, &ackPack, sizeof(ackPack), 0, (struct sockaddr*)&dest_addr, sizeof(dest_addr));

    if (sentBytes == -1) {
        perror("sendto");
        close(sockfd);
    }

    close(sockfd);
    printf("\n----- SENT ACK -----\n\n\n");
    free(ipStr);
    lastPackCache = &ackPack;
    return 0;
}

/*int optionsHtonl(DhcpPacket *pack) {
    uint8_t options[214];
    options_t *ops = pack->ops;

    //writeData(NULL, MAGIC_COOKIE_LEN, MAGIC_COOKIE_VAL);
    writeData(CLIENT_IDENT_HEX, CLIENT_IDENT_LEN, ops->client_id);
    writeData(SERVER_IDENT_HEX, SERVER_IDENT_LEN, ops->server_id);
    writeData(RENEWAL_TIME_HEX, RENEWAL_TIME_LEN, ops->renewal_time);
    writeData(REBINDING_TIME_HEX, REBINDING_TIME_LEN, ops->rebinding_time);
    writeData(IP_ADDR_LEASE_TIME_HEX, IP_ADDR_LEASE_TIME_LEN, ops->ip_lease_length);
    writeData(DOMAIN_NAME_HEX, DOMAIN_NAME_LEN, ops->domain_name);
    writeData(TIME_OFFSET_HEX, TIME_OFFSET_LEN, ops->time_offset);
    writeData(MAX_SIZE_HEX, MAX_SIZE_LEN, ops->max_size);
    writeData(SERVER_NAME_HEX, SERVER_IDENT_LEN, ops->server_name);

}

int sendNak(DhcpPacket* reqPack, int sock)
{
    loadStuff();

    clearOptionArr(); // Clear global options array

    DhcpPacket *nakPack = (DhcpPacket*)malloc(sizeof(DhcpPacket));

    struct sockaddr_in src_addr, dest_addr;

    memset(&src_addr, 0, sizeof(src_addr));
    memset(&dest_addr, 0, sizeof(dest_addr));

    src_addr.sin_family = AF_INET;
    src_addr.sin_addr.s_addr = htonl(INADDR_ANY);
    src_addr.sin_port = htons(67);

    dest_addr.sin_family = AF_INET;
    dest_addr.sin_port = htons(68);
    dest_addr.sin_addr.s_addr = htonl(BROADCAST_ADDR);

    if (bind(sock, (struct sockaddr*)&src_addr, sizeof(src_addr)) == -1) {
        perror("offer bind");
        close(sock);
    }

    ssize_t sent_bytes = sendto(sock, nakPack, sizeof(nakPack), 0, (struct sockaddr*)&dest_addr, sizeof(dest_addr));

    if (sent_bytes == -1) {
        fprintf(stderr, "Problem sending the Nak\n");
        return 1;
    }

    uint8_t clIdent[getOpLen(reqPack, 0x3D)];

    DhcpPacket *nakPack;

    boilerOffer(&nakPack, reqPack); // Write some boiler plate/default options to the packet

    setXid(&nakPack, reqPack->xid); // Set the session ID to that of the Discover packet

    int bitMask = getMaskNum(); 

    nakPack.siaddr = u8ToU32(serverIdent);

    for (int i = 0; i < sizeof(reqPack->chaddr); i++) {
        nakPack.chaddr[i] = reqPack->chaddr[i];
    }
    
    writeCookie(); // Write Magic Cookie to offer packet
    
    if (sock == -1) {
        perror("socket");
        exit(EXIT_FAILURE);
        return 1;
    }

    int broadcastEnable = 1;

    if (setsockopt(sock, SOL_SOCKET, SO_BROADCAST, &broadcastEnable, sizeof(broadcastEnable)) == -1) {
        perror("setsockopt (SO_BROADCAST)");
        close(sockfd);
        return 1;
    }

    struct sockaddr_in client_addr;
    memset(&client_addr, 0, sizeof(client_addr));

    uint8_t offer[16] = {NAK_HEX};
    uint8_t max_size[16] = {0x05, 0xDC};

    getFromOptionsRedux(reqPack, 0x3D, clIdent);

    writeData(DHCP_OP_MESSGAGE_HEX, 0x01, offer);
    writeData(CLIENT_IDENT_HEX, 0x07, clIdent);
    writeData(SERVER_IDENT_HEX, 0x04, serverIdent);
    writeData(0x39, 0x02, max_size);

    endOpsCombine(&nakPack); 

    uint32_t u = BROADCAST_ADDR;

    struct sockaddr_in src_addr, dest_addr;
    memset(&src_addr, 0, sizeof(src_addr));
    memset(&dest_addr, 0, sizeof(dest_addr));

    src_addr.sin_family = AF_INET;
    src_addr.sin_addr.s_addr = htonl(INADDR_ANY);
    src_addr.sin_port = htons(67);

    dest_addr.sin_family = AF_INET;
    dest_addr.sin_port = htons(68);
    dest_addr.sin_addr.s_addr = htonl(u);

    if (bind(sock, (struct sockaddr*)&src_addr, sizeof(src_addr)) == -1) {
        perror("offer bind");
        close(sock);
    }

    ssize_t sentBytes = sendto(sock, &nakPack, sizeof(nakPack), 0, (struct sockaddr*)&dest_addr, sizeof(dest_addr));

    if (sentBytes == -1) {
        perror("sendto");
        close(sock);
    }

    close(sock);
    printf("\n----- SENT OFFER -----\n\n\n");
    return 0;
}*/

int 
handleRelease(DhcpPacket* pack)
{

}

int 
handleInform(DhcpPacket* pack)
{

}
 
int 
handleDecline(DhcpPacket* pack)
{

}


int getOpLen(DhcpPacket* pack, uint8_t opCode)
{
    int opCodeInd = 0;
    int opCodeValLen = 0; 
    int p = 0;

    for (size_t i = 0; i < sizeof(pack->opCodes); i++) 
    {
        if (!opCodeExists(pack, opCode))
        {
            return 2;
        }

        if (pack->opCodes[i] == opCode)
        {
            opCodeInd = getAtIndex(pack->opCodeIndexes, i);
            opCodeValLen = pack->options[opCodeInd + 1]; 
            return opCodeValLen;
        }
    }

    return 0;
}

long howManyIps(int bitMask) {
    int g = 32 - bitMask;

    long addrs = pow(2, g);

    return addrs;
}

void clearOptionArr() {
    memset(&optionArr, 0, sizeof(optionArr));  

    for (int i = 0; i < sizeof(optionArr); i++) {
        optionArr[i] = 0x00;
    } 
}

void endOpsCombine(DhcpPacket *pack) {
    optionArr[opInd] = 0xFF;

    for (int i = 0; i < sizeof(optionArr); i++) {

        if (opInd < i) {
            pack->options[i] = 0x00; 
        }
        else {
           pack->options[i] = optionArr[i]; 
        }   
    }

    opInd = 0;
}


void writeIp(uint8_t* ptr, uint8_t ip[16]) {
    for (int i = 0; i < 4; i++) {
        ip[i] = ptr[i];
        //printf("router: %u\n",router[i] );
    }
}



int loadStuff() {

    if (strcmp(sqlSet->subnet, "auto") == 0)
    {
        getSubnetFromMask();  
        
    }
    else if (strcmp(sqlSet->subnet, "auto") != 0)
    {
        ipStrToU8(sqlSet->subnet, subnetMask);
    }

    if (strcmp(sqlSet->router, "auto") == 0)
    {  
        char* gate = (char*)malloc(32); getGateway(gate);
        ipStrToU8(gate, router);
        free(gate);
    }
    else if (strcmp(sqlSet->router, "auto") != 0)
    {
        ipStrToU8(sqlSet->router, router);
    }

    if (strcmp(sqlSet->dns, "auto") == 0)
    {
        getDNS();
    }
    else if (strcmp(sqlSet->dns, "auto") != 0)
    {
        ipStrToU8(sqlSet->dns, dns);
    }

    createRoleModel();
    ipStrToU8("192.168.1.186", serverIdent);
} 

int
getDNS ()
{
    char buf[256];
    char str[64];

    snprintf(str, sizeof(str), "resolvectl -i %s dns", sqlSet->interface);

    FILE* p = popen(str, "r");

    if (p == NULL)
    {
        fprintf(stderr, "Error - Problem getting DNS data\n");
        return 1;
    }

    fgets(buf, sizeof(buf), p);

    strtok(buf, " ");
    strtok(NULL, " ");
    strtok(NULL, " ");
    char* tok = strtok(NULL, " ");

    if (inet_addr(tok) == -1)
    {
        printf("Hmmm, can't find IPv4 DNS, just going to use gateway, maybe specify DNS in gdhcp.conf if local DNS is not gateway\n");
        for (int i = 0; i <= 3; i++)
        {
            router[i] = dns[i];
        }
    }
    else if (inet_addr(tok) != -1)
    {
        //ipStrToU8(tok, dns);
    }
    
    pclose(p);
    return 0;
}

int
getCurrentInterface(char* interfaceGlob)
{
    char buf[256];
    char tmpBuf[256];

    FILE* fp;

    fp = popen("ip link", "r");
    if (fp == NULL)
    {
        fprintf(stderr, "Error - Problem getting current interface, please specify in settings\n");
        return 1;
    }

    while (fgets(buf, sizeof(buf), fp) != NULL) { //Reads the conents of the pipe to buffe
        if (strstr(buf, "mode") != NULL) { // Checks if the line has the word default

            strcpy(tmpBuf, buf);
            strtok(tmpBuf, " ");
            char* interface = strtok(NULL, ": ");

            char *tok = strtok(buf, " "); // Cuts the buffer into pieces and sees wether it is a valid inet addr

            while (tok != NULL) { 
                
                if (strcmp(tok, "UP") == 0) {
                    printf("Interface %s is UP\n", interface);
                    strcpy(sqlSet->interface, interface);
                    pclose(fp);
                    return 0;
                }
                tok = strtok(NULL, " ");
            }
        }
    }

    pclose(fp);
    return 0;
}


/*int 
validateInterface(char* interface) 
{
    int fd;
    struct ifreq ifr;

    strcpy(ifr.ifr_name, interface);

    if (ioctl(fd, SIOCGIFFLAGS, &ifr) == -1)
    {
        perror("ioctl");
        close(fd);
    }

    if (ifr.ifr_flags)
    {
        printf("gggg");
    }
}*/

int
getSubnetFromMask() 
{
    uint8_t* sbNetPtr = (uint8_t*)malloc(64); 

    u32ToU8Be(maskToSubnet(getMaskNum()), sbNetPtr);

    subnetMask[0] = sbNetPtr[3]; 
    subnetMask[1] = sbNetPtr[2]; 
    subnetMask[2] = sbNetPtr[1]; 
    subnetMask[3] = sbNetPtr[0];

    free(sbNetPtr);
    return 0;
}

int getGateway(char* gate) { 
    FILE *fp;
    char buf[256];

    fp = popen("ip route", "r"); //Opens pipe to command "ip route"
    if (fp == NULL) {
        perror("Error opening pipe");
    }

    while (fgets(buf, sizeof(buf), fp) != NULL) { //Reads the conents of the pipe to buffe
        if (strstr(buf, "default") != NULL) { // Checks if the line has the word default

            char *tok = strtok(buf, " "); // Cuts the buffer into pieces and sees wether it is a valid inet addr

            while (tok != NULL) { 
                
                if (inet_addr(tok) != -1) {
                    strcpy(gate, tok);
                    break;
                }

                tok = strtok(NULL, " ");
            }
        }
    }

    pclose(fp);
    return 0;
}



int getMaskNum() {
    FILE *fp;
    char bits[32];
    char buf[1000];

    fp = popen("ip route", "r");
    if (fp == NULL) {
        perror("Error opening pipe");
    }
    
    while (fgets(buf, sizeof(buf), fp) != NULL) {
        if (strstr(buf, "/") != NULL) {
            char* tok = strtok(buf, " ");
            for (size_t i = 0; i < strlen(tok); i++) {
                if (tok[i] == '/') {
                    
                    if ((strlen(tok) - i) == 3) {
                        bits[0] = tok[i + 1]; bits[1] = tok[i + 2];
                    } else if ((strlen(tok) - i) == 2) {
                        bits[0] = tok[i + 1];                   
                    }

                    bits[strlen(bits) + 1] = '\0';

                    int ret = atoi(bits);
                    pclose(fp);
                    return ret;
                }
            }
        }
    }

    pclose(fp);
}

void boilerOffer(DhcpPacket *offPack, DhcpPacket *discPack) {
    offPack->op = 0x02;
    offPack->htype = 0x01;
    offPack->hlen = 0x06;
    offPack->hops = 0x00;
    offPack->flags = 0x0000;
    offPack->secs = 0x0000;
    offPack->ciaddr = discPack->ciaddr;

    for (size_t i = 0; i < 64; i++) {
        offPack->sname[i] = SERVER_NAME_VAL[i];
    }

    for (size_t i = 0; i < 128; i++) {
        offPack->file[i] = 0x00;
    }
}

void boilerAck(DhcpPacket *ackPack, DhcpPacket *reqPack) {
    ackPack->op = 0x02;
    ackPack->htype = 0x01;
    ackPack->hlen = 0x06;
    ackPack->hops = 0x00;
    ackPack->flags = 0x0000;
    ackPack->secs = 0x0000;
    ackPack->ciaddr = reqPack->ciaddr;
}

void setXid(DhcpPacket *pack, uint32_t olXid) {
    pack->xid = olXid;
}

int getFromOptions(uint8_t options[GLOBAL_OPTIONS_LEN], uint8_t opCode, uint8_t* retList) {

    int j = 4;
    uint8_t list[sizeof(*retList)];

    int leng = 0;
    int p = 0;

    for (int i = 0; options[j] != 0; i++) {

        if ((uint8_t)options[j] == opCode) {


            for (int l = j + 1; l <= (options[j + 1] + j); l++) {
                retList[p] = options[l + 1];
                p++;
            }
        }

        else if (options[j + 1] == 0 && list == NULL) 
        {
            for (size_t i = 0; i <= sizeof(*list); i++) 
            {
                retList[i] = 0x00;
            }
        }
        leng = options[j + 1];
        j += leng + 2;
    }     
    return 0;
}

/*uint8_t* test(uint8_t options[214], uint8_t opCode, size_t len) {
    size_t decOpCode = (uint8_t)opCode;

    for (size_t i = 0; i < sizeof(options); i++) 
    {
        if (options[i] == opCode) {

        }
    }
}*/


int writeCookie () {
    optionArr[0] = 0x63; optionArr[1] = 0x82; optionArr[2] = 0x53; optionArr[3] = 0x63;
    /*if (optionArr[0] == NULL || optionArr [3] == NULL) {
        fprintf(stderr, "Error - Writing DHCP Cookie (I ate it :)\n");
        return 1;
    }*/

    opInd = 4;

    return 0;
}

void handleReq(DhcpPacket *pack) {
    int len = 1;
    int j = 4;

    for (int i = 0; pack->options[j] != 0; i++) {//sees len too
        if (pack->options[j] == 55) {
            for (int l = j + 1; l <= (pack->options[j + 1] + j); l++) {
                uint8_t leng = len;
                switch (pack->options[l]) {
                    case 0x35: //53
                        printf("DHCP Messgage\n");
                        break;
                    case 0x37: //55
                        printf("Request List\n");
                        //readRequestList(dp, opInd, opLen);
                        break;
                    case 0x39: //57
                        printf("DHCP Max Size\n");
                        writeData(MAX_SIZE_HEX, leng, MAX_SIZE_VAL);
                        break;
                    case 0x3D: //61
                        printf("Client ID\n");
                        break;
                    case 0x32: //50
                        printf("Address Request\n");
                        break;
                    case 0x33: //51
                        printf("Address Time\n");
                        break;
                    case 0x06: //51
                        printf("DNS\n");
                        writeData(DNS_HEX, DNS_LEN, dns);
                        break;
                    case 0x09: //9
                        printf("LPR Server\n");
                        break;
                    case 0x79: //121
                        printf("Classless Route\n");
                        uint8_t classlessRoute[16] = {
                            0x20, 0xC0, 0xA8, 0x01,  // Router: 192.168.1.91
                            0x18, 0xC0, 0xA8, 0x01, 0x00,  // Subnet: 192.168.1.0
                            0x20, 0xFF, 0xFF, 0xFF, 0x00    // Mask: 255.255.255.0 (CIDR: /24)
                            // Add other entries if needed
                        }; //32, 192, 168, 1, 91, 192, 168, 1, 254, 24, 192, 168, 1, 0
                        
                        
                        //writeData(0x79, 0x0E, classlessRoute);
                        break;
                    case 0x03: //3
                        printf("Router\n");
                        writeData(ROUTER_HEX, ROUTER_LEN, router);
                        break;
                    case 0x0F: //15
                        printf("Domain Name\n");
                        writeData(DOMAIN_NAME_HEX, DOMAIN_NAME_LEN, DOMAIN_NAME_VAL);
                        break;
                    case 0x01: //1
                        printf("Subnet Mask\n");
                        writeData(SUBNET_MASK_HEX, SUBNET_MASK_LEN, subnetMask);
                        break;
                    default:
                        //printf("Option Code 0x%x OR %u\n", pack->options[l], pack->options[l]);
                        opReader((size_t)pack->options[i]);
                        break;
                    }
                }
        }
        len = pack->options[j + 1];
        j += len + 2;
    }
}


void writeData(uint8_t opCode, uint8_t len, uint8_t vals[16]) {
    int i = opInd;
    int k = 0;
    int length = (int)len;

    optionArr[i] = opCode;
    optionArr[i + 1] = len;

    i += 2;

    for (int j = i; j < 16 + i; j++) { //I equals first byte after length byte 
        
        if (j > (length + i - 1)) { // Past point in options[] where option length spans
            //
        } else { 
            optionArr[j] = vals[k];
        }
        k++;
    }

    opInd += length + 2;
}

int writeDataRedux(uint8_t options[214], uint8_t opCode, uint8_t len, void* value) {
    uint8_t data[len];


}


/*void printDiscover(DhcpPacket *pack) {
    printf("Client MAC Address: %02x:%02x:%02x:%02x:%02x:%02x\n",
        pack->chaddr[0], pack->chaddr[1], pack->chaddr[2],
        pack->chaddr[3], pack->chaddr[4], pack->chaddr[5]);
    
    int len = 0;
    int j = 4;

    for (int i = 0; pack->options[j] != 0; i++) {

        if (pack->options[j] == 55) {
            printf("\n// Requested //\n");
            for (int l = j + 1; l <= (pack->options[j + 1] + j); l++) {
                handleReq(pack->options[l], len);
            }
        }
        len = pack->options[j + 1];
        j += len + 2;
    } 
}*/


int readOptions(DhcpPacket *pack, int sock) {

    openlog("glorp DHCP", LOG_CONS | LOG_PID | LOG_NDELAY, LOG_LOCAL1);

    uint8_t mes;
    char reqIp[128];
    for (int i = 0; pack->options[i] != 255; i++) {
        //printf("item: 0x%x\n", pack->options[i]);
        if (pack->options[i] == 53) {
            //printf("Got 53: %u\n", pack->options[i + 2]);
            mes = pack->options[i + 2];
            break;

        } if (pack->options[i] == 61) {
            //printf("Got 61 (ident): %u\n", pack->options[i + 2]);

        } if (pack->options[i] == 50) {
            printf("Got 50 (req IP): %u.%u.%u.%u\n", pack->options[i + 2], pack->options[i + 3], pack->options[i + 4], pack->options[i + 5]);
            sprintf(reqIp, "%u.%u.%u.%u", pack->options[i + 2], pack->options[i + 3], pack->options[i + 4], pack->options[i + 5]);
        } 
    }

    switch(mes) {
        case DISCOVER_HEX:
            fprintf(stdout, "\n\n----- RECIEVED DISCOVER -----\n\n");
            syslog(LOG_INFO, "REC DISC");
            sendOffer(pack);
            //dhcpMain();
            break;
        case ACK_HEX:
            printf("\n\n----- SERVER GOT ACK ----- \n\n");
            //dhcpMain();
            break;
        case OFFER_HEX:
            printf("\n\n----- SERVER GOT OFFER -----\n\n");
            //dhcpMain();
            break;
        case REQUEST_HEX:
            fprintf(stdout, "\n\n----- RECIEVED REQUEST -----\n\n");
            syslog(LOG_INFO, "REC REQ");
            sendAck(pack);
            //dhcpMain();
            break;
        case DECLINE_HEX:
            fprintf(stdout, "\n\n----- GOT DENIED -----\n\n");
            //dhcpMain();
            break;
        case INFORM_HEX:
            fprintf(stdout, "\n\n----- INFORM -----\n\n");
            //dhcpMain();
            break;
        case RELEASE_HEX:
            fprintf(stdout, "\n\n----- RELEASE -----\n\n");
            //dhcpMain();
            break;
        case NAK_HEX:
            fprintf(stdout, "\n\n----- NAK -----\n\n");
            //dhcpMain();
            break;
        default:
            fprintf(stdout, "\n\n----- UNRECOGNIZED OPCODE %d-----\n\n", mes);
            //sendNak(pack, sock);
            //dhcpMain();
            return 0;
    }
    closelog();
    return EXIT_SUCCESS;
}


char* getOp(DhcpPacket dp, int opInd, int opLen) {
    char* opo = "Unknown Option Code";
    switch (dp.options[opInd]) {
        case 0x35: //53
            opo = "DHCP Message";
            break;
        case 0x37: //55
            opo = "Paremeter List";
            //readRequestList(dp, opInd, opLen);
            break;
        case 0x39: //57
            opo = "DHCP Max Size";
            break;
        case 0x3D: //61
            opo = "Client ID";
            break;
        case 0x32: //50
            opo = "Address Request";
            break;
        case 0x33: //51
            opo = "Address Time";
            break;
    }
    return opo;
}

void readRequestList(DhcpPacket *dp, int opInd, int opLen) {
    //printf("reg len: %d\n", opLen);
    for (int i = opInd + 2; i < opLen + 1; i++) {
        printf("Request list item: 0x%x\n", dp->options[i]);
    }
}

void dealFlag(char* flag, char* argList[256]) { // Post Parse Flag Processing

	if ((flagEquals(flag, "-s", "--s", "--start")) && argList != NULL) {
        printf("\n----- DHCP SERVER STARTED -----\n\n");
        createSettings();
        settingInit();
        sqlDBConnectTest();
		dhcpMain(TERMINAL_MODE);
    } else if ((flagEquals(flag, "-c", "--c", "--start")) && argList != NULL) {
		createSettings();
    } else if ((flagEquals(flag, "-cs", "--cs", "--start")) && argList != NULL) {
		char *argList[256] = {"archive-duplicates", "yes"};
        changeSetting(argList);
        //printf("changed setting\n");
    } else if ((flagEquals(flag, "-o", "--o", "--start")) && argList != NULL) {
		copyToOld();
        //printf("created settings \n");
    } else if ((flagEquals(flag, "-z", "--z", "--start")) && argList != NULL) {
		if (confSameOld()) {
            printf("They the saaaame\n");
        }
        else {
            printf("they difff\n");
        }
    }
    
}


bool flagEquals(char* flag, char* x, char* y, char* z) { // Returns true if 'flag' string equals any of the 3 'x,y,z' strings, false otherwise
	if ((strcmp(flag, x) == 0) || (strcmp(flag, y) == 0) || (strcmp(flag, z) == 0)) {
		return true;
	}

	return false;
}

bool isFlag(int argc, char *argv[], int i) { // Returns true if an arg starts with either '--' or '-'
	char *buf;
	char *buf2;

	buf = argv[i];
	buf2 = argv[i+1];

	if ((argv[i] == NULL) || (strcmp(argv[i], "\0") == 0)) {
		return false;
	}

	char buffer[3];
	sprintf(buffer, "%c%c", buf[0], buf[1]);
	if ((buf[0] == '-') || (strcmp(buffer, "--")) == 0) {
		return true;
	}
	else {
		return false;
	}
}

void info() {
    printf("blha\n");
}

void parser(int argc, char* argv[]) {
    int size = 0;
	char* strList[256];

	for (int i = 1; i < argc; i++) {

		if (isFlag(argc, argv, i) && (isFlag(argc, argv, i + 1) || isNullArg(argc, argv, i + 1))) { //Deal with lonely flag when next arg is flag
		
			dealFlag(argv[i], strList);

		} else if (!isFlag(argc, argv, i) && (isFlag(argc, argv, i + 1) || isNullArg(argc, argv, i + 1))) { //Add non-flag arg to list and then deal with it

			strList[size] = argv[i];
			size++;
			dealFlag(argv[i - size], strList);
			*strList = NULL;
			size = 0;

		} else if (!isFlag(argc, argv, i) && !isNullArg(argc, argv, i)) {

			strList[size] = argv[i];
			size++;

		} else if (isFlag(argc, argv, i)) {
            // IDK
		}
	}
}

bool isNullArg(int argc, char *argv[], int i) { // Returns true if arg is "\0" or NULL
	if ((argv[i] == NULL) || (strcmp(argv[i], "\0") == 0)) {
		return true;
	}
	return false;
}

int parseOptions(DhcpPacket *reqPack, DhcpPacket *ansPack) {
    if (!hasMagic(reqPack->options)) {
        printf("It dont have da magic womp womp\n");
        return 1;
    }

    ansPack->options[0] = 0x63; ansPack->options[1] = 0x82; ansPack->options[2] = 0x53; ansPack->options[3] = 0x63;

    for (int i = 4; reqPack->options[i] != 255; i++) {
        if (reqPack->options[i + 1] == 0xFF) { // Maybe they are parsed as uint8_ts
            ansPack->options[i] = 0xFF;
        }
        if (reqPack->options[i] == 0x32) { //Req ip 

            ansPack->options[i] = 0x32;
            ansPack->options[i + 1] = 0x01;
            ansPack->options[i + 2] = reqPack->options[i + 2];
            ansPack->options[i + 3] = reqPack->options[i + 3];
            ansPack->options[i + 4] = reqPack->options[i + 4];
            ansPack->options[i + 5] = reqPack->options[i + 5];

        } else if (reqPack->options[i] == 0x37) { //reqlist
            int len = reqPack->options[i + 1];
            for (int j = reqPack->options[i + 2]; j < (len + reqPack->options[i + 2]); j++) {
                //
            }
        } 
    }
    return 0;
}

bool hasMagic(uint8_t op[GLOBAL_OPTIONS_LEN]) {
    if (op[0] == 0x63 && op[1] == 0x82 && op[2] == 0x53 && op[3] == 0x63) {
        return true;
    }
    return false;
}

int sendDiscover() {
    char* buf[1024];

    DhcpPacket pack;
    memset(&pack, 0, sizeof(pack));

    pack.op = 1;
    pack.htype = 1;
    pack.hlen = 6;
    pack.hops = 0;
    pack.xid = 42069;

    pack.options[0] = 53;  // DHCP message type
    pack.options[1] = 1;   // Length of DHCP message type option
    pack.options[2] = 1;   // DHCPOFFER

    int sockfd = socket(AF_INET, SOCK_DGRAM, 0);

    if (sockfd == -1) {
        perror("socket");
        exit(EXIT_FAILURE);
        return 1;
    }

    int broadcastEnable = 1;

    if (setsockopt(sockfd, SOL_SOCKET, SO_BROADCAST, &broadcastEnable, sizeof(broadcastEnable)) == -1) {
        perror("setsockopt (SO_BROADCAST)");
        close(sockfd);
        return 1;
    }

    struct sockaddr_in client_addr;
    memset(&client_addr, 0, sizeof(client_addr));

    client_addr.sin_family = AF_INET;
    client_addr.sin_addr.s_addr = htonl(INADDR_ANY);
    client_addr.sin_port = htons(SERVER_PORT);

    if (bind(sockfd, (struct sockaddr*)&client_addr, sizeof(client_addr)) == -1) {
        perror("bind failed");
        close(sockfd);
        return 1;
    }

    ssize_t sentBytes = sendto(sockfd, &pack, sizeof(pack), 0, (struct sockaddr*)&client_addr, sizeof(client_addr));

    if (sentBytes == -1) {
        perror("sendto");
        close(sockfd);
    }
    printf("sent discover\n");

    close(sockfd);
    return 0;
}

