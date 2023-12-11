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


/*int leap_frog_pack_ops(vanilla_dhcppacket_t *pack) 
{
    int p = 0;

    if (&pack->options == NULL) 
    {
        fprintf(stderr, "Error - Empty options array when parsing through op codes\n");
    }

    for (size_t i = 4; i <= GLOBAL_OPTIONS_LEN - 1;) 
    {
        if ((int)pack->options[i-1] == 0x00 || (int)pack->options[i-1] == 0xFF) 
        {
            break;
        }

        //pack->opCodes[p] = pack->options[i]; setAtIndex(pack->op_code_indexes, p, i);
        i+= ((int)pack->options[i+1] + 2);
        p++;
    }

    return 0;
}

int leap_frog_options(uint8_t *options, int *) {
    return 1;
}*/


char *get_char_val(option_t *option) {
    return option->char_value;
}

/*void *leapFrogOps(struct dhcppacket *dhcpPack) {
    int p = 0;

    if (&pack->options == NULL) 
    {
        fprintf(stderr, "Error - Empty options array when parsing through op codes\n");
    }

    for (size_t i = 4; i <= GLOBAL_OPTIONS_LEN - 1;) 
    {
        if ((int)pack->options[i-1] == 0x00 || (int)pack->options[i-1] == 0xFF) 
        {
            break;
        }

        //pack->opCodes[p] = pack->options[i]; setAtIndex(pack->op_code_indexes, p, i);
        i+= ((int)pack->options[i+1] + 2);
        p++;
    }

    return 0;
}*/

void leap_frog_ops(dhcppacket_t *dhcp_pack, dhcp_options_t *options) {
    int n = 0;

    printf("in leap frog\n");

    int size = sizeof(dhcp_pack->options) / sizeof(dhcp_pack->options[0]);

    options->options_head = (option_t*)malloc(sizeof(option_t));
    options->options_head->next = NULL;
    options->options_head->prev = NULL;

    if (&dhcp_pack == NULL || &options == NULL) {
        fprintf(stderr, "Null ptr dhcp pack or options\n");
        return;
    }

    for (int i = 0; i < size;) {
        if (dhcp_pack->options[i-1] == 0xFF) {
            break;
        } 
        
        option_t *op = (option_t*)malloc(sizeof(option_t));

        op->char_value = "glorp";

        addToEnd((options->options_head), op);
        
        i++;

        n++;
    }   

    /*options->options_list = (node_t*)malloc(sizeof(node_t));
    options->options_list->c = 0;
    options->options_list->next = NULL;

    addToEnd(options->options_list, 69);
    addToEnd(options->options_list, 420);

    iterate(options->options_list);*/
}

//void traverseOptions(options_t *options) {
    //options->intent->get_value = getCharValue;
    //printf("intent %s\n", options->intent->get_value(options->intent));
//}

uint8_t *get_u8_val(option_t *option) {
    return option->u8_value;
}

int get_len(option_t *option) {
    return option->len;
}

uint8_t get_op_code(option_t * option) {
    return option->op_code;
}

void set_len(option_t* option, int new_len) {
    option->len = new_len;
}

void set_op_code(option_t *option, uint8_t new_op_code) {
    option->op_code = new_op_code;
}

void set_u8_val(option_t *option, uint8_t* val_ptr) {
    option->u8_value = val_ptr;
}

void set_char_val(option_t *option, char* val_ptr) {
    option->char_value = val_ptr;
}

int is_dhcp(dhcppacket_t *dhcp_pack) { 

    int dhcp_ops[] = {1, 2, 3, 5};
    int size = sizeof(dhcp_ops) / sizeof(dhcp_ops[0]);

    for (int i = 0; i < size; i++) {

        int n = dhcp_ops[i];

        if (n == dhcp_pack->op) {
            return n;
        }
    }

    return -1;
}