#include "included.h"
#include "dhcppacket.h"

#ifndef DUO_NODE_H
    #define DUO_NODE_H
    
    #define ACCESSED 1
    #define NOT_ACCESSED 0
    
    typedef struct node {
        int val;
        struct node *next;
        struct node *prev;
    } node_t;

    int popLast(option_t* head);
    int pop(option_t** head);
    void addToStart(option_t** head, int newVal); 
    void addToEnd(option_t* head, int newVal);
    void iterate(option_t* head);
    int remByInd(option_t** head, int ind);
    int getAtIndex(option_t *head, int index); 
    void setAtIndex(option_t *head, int index, int newVal);
    void freeNodes(option_t *head);

#endif