#include <stdio.h>
#include "obj.h"

int main() {
    duo_node_t *head;

    head->next->val = (void*)42;

    printf("val: %d\n", (void*)getAtIndex(head, 1));

    return 0;
}