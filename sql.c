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
int arrUint8Empty(uint8_t arr[], size_t s);

int 
leaseToDB(LeasedClient* lcPtr) // Leases LeasedClient Object to leases DB
{
    PGresult* res;

    char connStr[1000];

    snprintf(connStr, sizeof(connStr), "host=%s dbname=%s user=%s password=%s", sqlSet->host, sqlSet->database_name, sqlSet->user_name, sqlSet->password);

    PGconn* conn = PQconnectdb(connStr); // Connection sting for DB   

    if (PQstatus(conn) != CONNECTION_OK) // Continue if Connection is OK
    {
        fprintf(stderr, "Connection to database failed: %s", PQerrorMessage(conn));
        PQfinish(conn);
        return 1;
    } 

    // Check to make sure each member of LeasedClient is not NULL
    if (arrUint8Empty(lcPtr->chaddr, 16) == 0) 
    {
        printf("Error - Hardware adress not found when making lease\n");
        PQfinish(conn);
        return 1;
    }
    if (lcPtr->leased_ip == NULL) 
    {
        printf("Error - Problem with Requested IP when making lease\n");
        PQfinish(conn);
        return 1;
    }
    if ((lcPtr->lease_length, 4) == 0) 
    {
        printf("Error - Problem with Lease Length when making lease\n");
        PQfinish(conn);
        return 1;
    }
    if ((lcPtr->rebinding_time, 4) == 0) 
    {
        printf("Error - Problem with Rebinding Time when making lease\n");
        PQfinish(conn);
        return 1;
    }
    if ((lcPtr->renewal_time, 4) == 0) 
    {
        printf("Error - Problem with Renewal Time when making lease\n");
        PQfinish(conn);
        return 1;
    }

    char com[1000];

    // Send command
    snprintf(com, sizeof(com),"INSERT INTO leases (ip_address, mac_address, lease_len, rebinding_len, renewal_len) VALUES ('%s','%s', '%d', '%d', '%d');", lcPtr->leased_ip, lcPtr->chaddr, lcPtr->lease_length, lcPtr->rebinding_time, lcPtr->renewal_time);

    res = PQexec(conn, com); // Execute command

    // Exit connection gracefully
    PQclear(res);
    PQfinish(conn);

    // Return success 
    return 0;
}

char*
getConnStr (char* connStr)
{
    snprintf(connStr, sizeof(connStr), "host=%s dbname=%s user=%s password=%s", sqlSet->host, sqlSet->database_name, sqlSet->user_name, sqlSet->password); 

    return connStr;
}

int 
sqlDBConnectTest() 
{
    char connStr[256];

    snprintf(connStr, sizeof(connStr), "host=%s dbname=%s user=%s password=%s", sqlSet->host, sqlSet->database_name, sqlSet->user_name, sqlSet->password);
    PGconn* conn = PQconnectdb(connStr);

    if (PQstatus(conn) != CONNECTION_OK) // Continue if Connection is OK
    {
        fprintf(stderr, "Connection to database failed: %s", PQerrorMessage(conn));
        PQfinish(conn);
        return 1;
    } 
    else 
    {
        printf("Success! - Connected to DB\n");
        PQfinish(conn);
    }
}


bool 
checkIfLeased(char* ip) // Checks if IP already has a lease in the leases DB, returns True of it does
{
    char connStr[256];

    printf("ip: %s\n", ip);

    snprintf(connStr, sizeof(connStr), "host=%s dbname=%s user=%s password=%s", sqlSet->host, sqlSet->database_name, sqlSet->user_name, sqlSet->password);
    PGconn* conn = PQconnectdb(connStr);

    if (PQstatus(conn) != CONNECTION_OK) // Continue if Connection is OK
    {
        fprintf(stderr, "Connection to database failed: %s", PQerrorMessage(conn));
        PQfinish(conn);
        return 1;
    } 

    if (ip == NULL) 
    {
        printf("Error - IP Adresses passed when chacking for leases was NULL\n");
        return 1;
    }

    char com[1000];

    snprintf(com, sizeof(com), "SELECT COUNT(*) FROM leases WHERE ip_address = '%s';", ip);

    PGresult *res = PQexec(conn, com); // Execute command

    if (PQresultStatus(res) != PGRES_TUPLES_OK) 
    {
        fprintf(stderr, "Query execution failed: %s", PQresultErrorMessage(res));

        PQclear(res); // Exit connection gracefully
        PQfinish(conn);

        return 1; // Exit with failure
    }

    int rowCount = atoi(PQgetvalue(res, 0, 0)); // Get values from res and convert to int rowCount

    // Check if the entry exists, if rowCount > 0, it does exist
    if (rowCount > 0) 
    {
        return true;
    } 
    else 
    {
        return false;
    }

    // Exit connection gracefully
    PQclear(res);
    PQfinish(conn);

    return false; 
}

int
getUnleasedIp(char* unleasedRet, int bits)
{   
    char str[256];
    uint32_t netAddr = roleModel << 8;
    uint32_t ipAddr;
    bool check = false;
    
    for (int i = 2; i < (1 << (32 - bits)) - 2; i++) {
        ipAddr = netAddr + i;

        snprintf(str, sizeof(str),"%u.%u.%u.%u", 
        (ipAddr >> 24) & 0xFF,
        (ipAddr >> 16) & 0xFF,
        (ipAddr >> 8) & 0xFF,
        ipAddr & 0xFF);

        //printf("str: %s\n", str);

        check = checkIfLeased(str);

        if (!check)
        {
            strcpy(unleasedRet, str);
            return 0;
        }
    }
    return 0; 
}

bool
checkIfMacHasLease(char* mac)
{
    char connStr[256];

    snprintf(connStr, sizeof(connStr), "host=%s dbname=%s user=%s password=%s", sqlSet->host, sqlSet->database_name, sqlSet->user_name, sqlSet->password);
    PGconn* conn = PQconnectdb(connStr);

    if (PQstatus(conn) != CONNECTION_OK) // Continue if Connection is OK
    {
        fprintf(stderr, "Connection to database failed: %s", PQerrorMessage(conn));
        PQfinish(conn);
        return 1;
    } 

    if (mac == NULL) 
    {
        printf("Error - Mac passed when checking for leases was NULL\n");
        return 1;
    }

    char com[1000];

    snprintf(com, sizeof(com), "SELECT COUNT(*) FROM leases WHERE mac_address = '%s';", mac);

    PGresult *res = PQexec(conn, com); // Execute command

    if (PQresultStatus(res) != PGRES_TUPLES_OK) 
    {
        fprintf(stderr, "Query execution failed: %s", PQresultErrorMessage(res));

        PQclear(res); // Exit connection gracefully
        PQfinish(conn);

        return 1; // Exit with failure
    }

    int rowCount = atoi(PQgetvalue(res, 0, 0)); // Get values from res and convert to int rowCount

    // Check if the entry exists, if rowCount > 0, it does exist
    if (rowCount > 0) 
    {
        return true;
    } 
    else 
    {
        return false;
    }

    // Exit connection gracefully
    PQclear(res);
    PQfinish(conn);

    return false;    
}

int 
clearAllLeases() 
{
    PGresult* res;
    PGconn* conn = PQconnectdb("host=localhost dbname=dhcp user=grant password=bowieboom123");

    if (PQstatus(conn) != CONNECTION_OK) {
        printf("Error - Problem connection to DB to delete all leases\n");
        PQfinish(conn);                
    }

    char com[1000];

    snprintf(com, sizeof(com), "DELETE FROM leases;");

    res = PQexec(conn, com);

    PQclear(res);
    PQfinish(conn);
    return 0;
}


int 
sendSQL(char* command) // General use function for sending SQL command as String
{
    PGconn *conn = PQconnectdb("host=localhost dbname=dhcp user=grant password=bowieboom123");

    if (PQstatus(conn) != CONNECTION_OK) // Continue if Connection is OK
    {
        fprintf(stderr, "Connection to database failed: %s", PQerrorMessage(conn));

        PQfinish(conn); // Exit connection

        return 1; // Return failure
    }

    PGresult* res = PQexec(conn, command); // Execute command

    if (PQresultStatus(res) != PGRES_TUPLES_OK) // Checks if command was sent successfully
    {
        fprintf(stderr, "Error - Failed when sending SQL command\n");

        PQclear(res); // Exit connection gracefully
        PQfinish(conn);

        return 1; // Exit with failure
    }

    return 0; // Exit success
} 

int 
removeLeaseByIp(char* leasedIp) // Removes lease from client, identified by IP leased
{
    PGresult* res;

    char connStr[1000];

    snprintf(connStr, sizeof(connStr), "host=%s dbname=%s user=%s password=%s", sqlSet->host, sqlSet->database_name, sqlSet->user_name, sqlSet->password);

    PGconn* conn = PQconnectdb(connStr); // Connection sting for DB  

    if (PQstatus(conn) != CONNECTION_OK) // Continue if Connection is OK
    {
        fprintf(stderr, "Error - Problem connecting to DB to delete lease by IP\n");

        PQfinish(conn); // Exit connection gracefully

        return 1; // Exit with failure
    }

    char com[1000];

    snprintf(com, sizeof(com),"DELETE FROM leases WHERE ip_address='%s';", leasedIp);

    res = PQexec(conn, com);    

    if (PQresultStatus(res) != PGRES_TUPLES_OK) 
    {
        fprintf(stderr, "Error - Command could not be executed when removing lease by ip\n");

        PQfinish(conn); // Exit connection gracefully

        return 1; // Exit with failure
    }

    PQclear(res); // Exit connection gracefully
    PQfinish(conn);

    return 0; // Exit success
}

int 
arrUint8EmptySql(uint8_t arr[], size_t s) // Checks whether given uint8_t array is empty, 1 if not empty 0 if empty
{ 
    for (size_t i = 0; i < s; i++) 
    {
        if (arr[i] != 0) 
        {
            return 1; // Return non empty
        }
    }

    return 0; // Return empty
}
