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

void info();
void parser(int argc, char *argv[]);
void dealFlag(char* flag, char* argList[256]);
bool flagEquals(char* flag, char* x, char* y, char* z);
bool isFlag(int argc, char *argv[], int i);
bool isNullArg(int argc, char *argv[], int i);

int dhcp_main(int mode);
int read_options(dhcppacket_t *dhcp_packet, int sock);
int send_offer(dhcppacket_t *dhcp_pack, int sockfd);


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

int dhcp_main(int mode) {

    //clearOptionArr();
    
    //loadStuff();

    int sock;

    struct sockaddr_in server_addr, client_addr;

    if (mode == 0) {
        sock = socket(AF_INET, SOCK_DGRAM, 0);  
    }

    if (sock == -1) {
        fprintf(stdout, SD_ERR "Unable to get file descriptor for socket\n");
        sd_notify(0, "STOPPING=1");
        return -1;
    }
     
    memset(&server_addr, 0, sizeof(server_addr)); 

    server_addr.sin_family = AF_INET; 
    server_addr.sin_addr.s_addr = htonl(INADDR_ANY); 
    server_addr.sin_port = htons(SERVER_PORT); 

    bind(sock, (struct sockaddr*)&server_addr, sizeof(server_addr)); 

    //sd_notify(0, "READY=1"); // Notify systemd that we are READY

    while(1) {
        socklen_t len = sizeof(client_addr); 
        char buf[1024]; 
        memset(buf, 0, sizeof(buf));
        recvfrom(sock, buf, sizeof(buf), 0, (struct sockaddr*)&client_addr, &len);

        dhcppacket_t *dhcp_pack = (dhcppacket_t*)buf; 

        dhcp_options_t *ops = (dhcp_options_t*)malloc(sizeof(dhcp_options_t));

        /*set_char_val(op, "gooptown");

        uint8_t foo[] = {0x0a, 0x0a, 0x0a};

        set_u8_val(op, foo);

        uint8_t *bar = get_u8_val(op);

        printf("glrop: %s\n", get_char_val(op));

        printf("foobat: %d\n", *bar);

        free(op);

        break;*/

        if (dhcp_pack->op != 0) {

            //read_options(dhcp_pack, sock);
            //send_offer(dhcp_pack, sock);
            leap_frog_ops(dhcp_pack, ops);

            iterate(ops->options_head);

            freeNodes(ops->options_head);

            free(ops);
            
            break;
        }
    }
    close(sock);
    return EXIT_SUCCESS;
}

/*int send_offer(dhcppacket_t *dhcp_pack, int sockfd) {// Recieved data buffer 

    //loadStuff();

    //leapFrogOps(discPack);

    uint8_t ipU8[getOpLen(discPack, 0x32)];
    uint8_t clIdent[getOpLen(discPack, 0x3D)];

    getFromOptionsRedux(discPack, 0x32, ipU8);
    getFromOptionsRedux(discPack, 0x3D, clIdent);

    char* ipStr = (char*)malloc(32);

    uint32_t ipU32 = u8ToU32(ipU8);

    bool check = isCorrectMask(//);

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
}*/

void dealFlag(char* flag, char* argList[256]) { // Post Parse Flag Processing

	if ((flagEquals(flag, "-s", "--s", "--start")) && argList != NULL) {
        printf("\n----- DHCP SERVER STARTED -----\n\n");
        //createSettings();
        //settingInit();
        //sqlDBConnectTest();
		dhcp_main(0);
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

int read_options(dhcppacket_t *dhcp_pack, int sock) {

    int dhcp_val = is_dhcp(dhcp_pack);

    if (dhcp_val == -1) {
        return 1;
    }

    switch (dhcp_val) {
        case 1: 
            // Discover
            printf("disc\n");
            break;
        case 2:
            // Offer
            break;
        case 3: 
            // Request
            printf("req\n");
            break;
        case 5: 
            // Ack 
            break;
        default:
            return 1;
    }

    /*printf("here\n");

    dhcp_pack->optionsP->traverse_options = traverseOptions;

    dhcp_pack->optionsP->intent->char_value = "glorp_me";

    printf("%s\n", dhcp_pack->optionsP->intent->char_value);

    dhcp_pack->optionsP->traverse_options(dhcp_pack->optionsP);*/

}



/*

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
    return EXIT_SUCCESS;*/

bool isNullArg(int argc, char *argv[], int i) { // Returns true if arg is "\0" or NULL
	if ((argv[i] == NULL) || (strcmp(argv[i], "\0") == 0)) {
		return true;
	}
	return false;
}