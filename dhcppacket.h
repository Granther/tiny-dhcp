#include "included.h"

#ifndef DHCPPACKET_H
    #define DHCPPACKET_H

    typedef struct option {
        uint8_t op_code;
        int len;
        char *char_value;
        uint8_t *u8_value;

        struct option *next;
        struct option *prev;

    } option_t;

    typedef struct dhcp_options {

        //option_t options_array[64];

        // add to 

        option_t *options_head;

    } dhcp_options_t;
      

    typedef struct dhcppacket {
        uint8_t op;            
        uint8_t htype;         
        uint8_t hlen;        
        uint8_t hops;          
        uint32_t xid;        
        uint16_t secs;         
        uint16_t flags;      
        uint32_t ciaddr;     
        uint32_t yiaddr;     
        uint32_t siaddr;        
        uint32_t giaddr;        
        uint8_t chaddr[16];    
        uint8_t sname[64];       
        uint8_t file[128];     
        uint8_t options[214];  

        uint8_t opCodes[16];

        dhcp_options_t *optionsP;

        void (*leap_frog_ops) (struct dhcppacket *dhcp_pack);

    } dhcppacket_t;

    char *getValue(struct option *option);

    void leapFrogOps(struct dhcppacket *dhcpPack);

    void traverseOptions(struct dhcp_options *options);

    int is_dhcp(dhcppacket_t *dhcp_pack);

    char* get_char_val(option_t *option);

    uint8_t *get_u8_val(option_t *option);

    int get_len(option_t *option);

    uint8_t get_op_code(option_t * option);

    void set_len(option_t* option, int new_len);

    void set_op_code(option_t *option, uint8_t new_op_code);

    void set_u8_val(option_t *option, uint8_t* val_ptr);

    void set_char_val(option_t *option, char* val_ptr);
    
    void leap_frog_ops(dhcppacket_t *dhcp_pack, dhcp_options_t *options);

#endif