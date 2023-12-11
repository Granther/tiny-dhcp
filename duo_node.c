#include "duo_node.h"

void iterate(option_t* head)
{
    option_t* cur = head;

    while (cur != NULL)
    {
        printf("%s\n", cur->char_value);
        cur = cur->next; // cur becomes a pointer to the next item after the pointer of curs current value
    }
}

void freeNodes(option_t* head) {
    option_t* cur = head;
    option_t* next;

    while (cur != NULL) 
    {
       next = cur->next;
       free(cur);
       cur = next;
    }
}

void addToEnd(option_t* head, option_t *newOption)
{
    option_t* cur = head;

    while (cur->next != NULL)
    {
        cur = cur->next;
    }

        // After loop exits, cur = last item in list

    cur->next = newOption;
    cur->next->prev = cur;
    cur->next->next = NULL; // Always set tail of list to NULL
}

void addToStart(option_t** head, int newVal) // The double pointer stores the address of a pointer to a node
{
        option_t* newNode;
        newNode = (option_t*)malloc(sizeof(option_t));

        newNode->next = *head;
        newNode->prev = NULL;
        newNode->next->prev = newNode; 

        newNode->char_value = newVal;
        *head = newNode; 
}


int pop(option_t** head) 
{
    option_t* nextNode = NULL;

    if (*head == NULL)
            return -1;

    nextNode = (*head)->next; 

    free(*head);

    *head = nextNode; 
    (*head)->prev = NULL;

    return 0;
}

int popLast(option_t* head) 
{
    if (head->next == NULL)
        return 0;

    option_t* cur = head;

    while (cur->next->next != NULL) // Go to the second to last node in the list
        cur = cur->next;

    free(cur->next); // The ->next pointer is the  last node in the list, NULL that pointer 
    cur->next = NULL;
    return 0;
}

int remByInd(option_t **head, int index) {

    option_t* cur = *head;
    option_t* tmp = NULL;

    if (index == 0) {
        pop(head);
        return 0;
    }

    if (cur->next == NULL) {
        return -1;
    }

    for(int i = 0; i < index - 1; i++) { 
        if (cur->next == NULL) {  
            return -1;
        }

        cur = cur->next; 
    }
    
    tmp = cur;

    cur->next->prev = cur->prev;
    cur->prev->next = cur->next;

    free(tmp);

    printf("should be at index %d: %d\n", index, cur->char_value);

    return 0;
}

int getAtIndex(option_t *head, int index) {
    int count = 0;

    option_t *cur = head;

    while (count < index) {
        cur = cur->next;
        count++;
    }

    return cur->char_value;
}

void setAtIndex(option_t *head, int index, int newVal) {
    int count = 0; 

    option_t *cur = head;

    while(count < index) {
        if (cur->next == NULL) {
            addToEnd(head, 0);
        }
        cur = cur->next;
        count++;
    }

    cur->char_value = newVal;

    return;
}
