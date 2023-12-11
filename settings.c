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

#define MAX_STRING_LENGTH 256

Settings *sqlSet;
Settings set;


uint8_t subnetMask[16];
uint8_t router[16];
uint8_t dns[16];
uint8_t serverIdent[16];
uint32_t roleModel;
char* networkInterface;

//vanilla_dhcppacket_t* lastPackCache;


void
settingInit() 
{
    sqlSet = (Settings*)malloc(256);

    sqlSet->database_name = (char*)malloc(64);
    sqlSet->host = (char*)malloc(64);
    sqlSet->leases_name = (char*)malloc(64);
    sqlSet->user_name = (char*)malloc(64);
    sqlSet->password = (char*)malloc(64);
    sqlSet->dns = (char*)malloc(64);
    sqlSet->router = (char*)malloc(64);
    sqlSet->subnet = (char*)malloc(64);
    sqlSet->interface = (char*)malloc(64);

    /*strcpy(sqlSet->database_name, "dhcp");
    strcpy(sqlSet->host, "localhost");
    strcpy(sqlSet->leases_name, "leases");
    strcpy(sqlSet->user_name, "grant");
    strcpy(sqlSet->password, "bowieboom123");*/

    getValFromSet("database-name", sqlSet->database_name);
    getValFromSet("host", sqlSet->host);
    getValFromSet("leases-name", sqlSet->leases_name);
    getValFromSet("user-name", sqlSet->user_name);
    getValFromSet("password", sqlSet->password);

    getValFromSet("dns", sqlSet->dns);
    getValFromSet("router", sqlSet->router);
    getValFromSet("subnet", sqlSet->subnet);
    getValFromSet("interface", sqlSet->interface);
    sqlSet->mode = TERMINAL_MODE;
}

int changeSetting(char* argList[256]) { // Not done

	char buf[256];
	int line = 0;
	char res[256];

	strcpy(res, argList[0]);
	strcat(res, ":");
	strcat(res, argList[1]);

    //run val type check

	FILE *original = fopen("gdhcp.conf", "r");
    //FILE *originalW = fopen("gdhcp.conf", "w");
	FILE *tmp = fopen("temp.conf", "w");

	while (fgets(buf, sizeof(buf), original) != NULL) {
		line++;
        
        char* setName = strtok(buf, ":");

        printf("setname: %s\n", setName);

        if (strcmp(setName, argList[0]) == 0) {
            printf("found1\n");
        }
	}

	fclose(original); fclose(tmp); //fclose(originalW);
    fprintf(stdout, "Success - Changed Setting\n");
	return 0;
}

// iterate through settings while copying it to temp, once we find setting name of which the value we would like to change
// change that line before copying it to temp, copy everything back from temp to org

int createSettings() { // Creates 'backstore.conf' if it does not exist, writes default settings

	char buf[256];

	const char *filename = "gdhcp.conf";
    const char *old = "/var/lib/gdhcp/gdhcp.old";
    DIR *dir = opendir("/var/lib/gdhcp");

	if (dir == NULL) {
        printf("/var/lib/gdhcp does not exist...attempting to create...\n");
        mkdir("/var/lib/gdhcp", 0755);

        DIR *dir = opendir("/var/lib/gdhcp");
        if (dir == NULL) {
            fprintf(stderr, "Error - Problem creating /var/liv/gdhcp...probably permissions\n");
            closedir(dir);
            return 1;
        }

		closedir(dir);
	}

	if (access(filename, 0) != 0) {
		printf("gdhcp.conf does not exist, creating it...\n");

        FILE *file = fopen(filename, "w");
        
        if (access(filename, 0) != 0) {
            fprintf(stderr, "Error - Couldn't create gdhcp.conf...probably permissions\n");
            return 1;
        }

        fprintf(file, "#operation settings\n\n");
		fprintf(file, "archive-duplicates:no\n");
        fprintf(file, "database-name:dhcp\n");
        fprintf(file, "leases-name:leases\n");
        fprintf(file, "user-name:grant\n");
        fprintf(file, "password:bowieboom123\n");
        fprintf(file, "host:localhost\n");

        fprintf(file, "\n#dhcp settings\n\n");
        fprintf(file, "dns:auto\n");
        fprintf(file, "router:auto\n");
        fprintf(file, "subnet:auto\n");
        fprintf(file, "interface:auto\n");

        fclose(file);
	}

    if (access(old, 0) != 0) {
		printf("/var/lib/gdhcp/gdhcp.old does not exist, creating it...\n");

        FILE *oldFile = fopen(old, "w");
        fclose(oldFile);

        if (access(old, 0) != 0) {
            fprintf(stderr, "Error - Couldn't create gdhcp.old...probably permissions\n");
            return 1;
        }
	}

	FILE *file = fopen("gdhcp.conf", "r");
    FILE *oldFile = fopen(old, "w");

	while (fgets(buf, sizeof(buf), file) != NULL) {
		//char* val = readSetting(buf, 1);
		//char* name = readSetting(buf, 2);
	}

    fprintf(stdout, "Success - Created all necessary Dirs and Files\n");

	fclose(file);
    fclose(oldFile);
}

int copyToOld() {

    char buf[256];

    FILE* org = fopen("gdhcp.conf", "r");
    FILE* old = fopen("/var/lib/gdhcp/gdhcp.old", "w");

    while (fgets(buf, sizeof(buf), org) != NULL) {
        fprintf(old, "%s", buf);
    }
}

bool confSameOld() {
    char currBuf[256];
    char oldBuf[256];

    FILE* org = fopen("gdhcp.conf", "r");
    FILE* old = fopen("/var/lib/gdhcp/gdhcp.old", "r");


    while(fgets(currBuf, sizeof(currBuf), org) != NULL && fgets(oldBuf, sizeof(oldBuf), old) != NULL) {
        printf("oldbuf: %s\n", oldBuf); printf("currbuf: %s\n", currBuf);
        if (strcmp(oldBuf, currBuf) != 0) {
            return false;
        }
    }
    fclose(org); fclose(old);
    return true;
}

bool fileNull(FILE* file) {
    char buf[256];

    if (fgets(buf, sizeof(buf), file) == NULL) {
        return true;
    }
    
    return false;
}

int getValFromSet(char* setName, char* setting) {
    char buf[256];

    FILE* file = fopen("/home/grant/Desktop/gdhcp/gdhcp.conf", "r");

    while(fgets(buf, sizeof(buf), file) != NULL) 
    {  
        char* name = (char*)malloc(32);
        char* val = (char*)malloc(32);
        
        readSetting(buf, val, name); 
        
        if (strcmp(name, setName) == 0) 
        {
            strcpy(setting, val);

            fclose(file); free(name); free(val);

            return 0;
        } 
        free(name); free(val);
    }
    fclose(file);
    return 0;
}

int readSetting(char* buf, char* value, char* settingName) {
    bool foundCol = false;

    if (buf[0] == '#' || buf[0] == '\n')
    {
        return 1;
    }

    char* bufBefCol = strtok(buf, ":");
    char* bufAftCol = strtok(NULL, "\n");

    strcpy(value, bufAftCol);
    strcpy(settingName, bufBefCol);

    return 0;
}

/*sqlSet = (Settings*)malloc(8000);
    memset(sqlSet, 0, sizeof(sqlSet));
    
    sqlSet->database_name = (char *)malloc(10000);
    printf("db-name-memaddr: %zu\n", &sqlSet->database_name);
    sqlSet->leases_name = (char *)malloc(10000);
    printf(" leases-memaddr: %zu\n", &sqlSet->leases_name);

    sqlSet->user_name = (char *)malloc(MAX_STRING_LENGTH);
    sqlSet->password = (char *)malloc(MAX_STRING_LENGTH);
    sqlSet->host = (char *)malloc(MAX_STRING_LENGTH);

    // Check if memory allocation was successful
    if (sqlSet->database_name == NULL || sqlSet->leases_name == NULL || sqlSet->user_name == NULL ||
        sqlSet->password == NULL || sqlSet->host == NULL) {
        fprintf(stderr, "Error - Memory allocation failed\n");
        exit(EXIT_FAILURE);
    }

    strcpy(sqlSet->database_name, getValFromSet("database-name"));
    strcpy(sqlSet->leases_name, getValFromSet("leases-name"));
    strcpy(sqlSet->user_name, getValFromSet("user-name"));
    strcpy(sqlSet->password, getValFromSet("password"));
    strcpy(sqlSet->host, getValFromSet("host"));*/