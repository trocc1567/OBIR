#ifndef RPN_STACK_H
#define RPN_STACK_H

void makeEmpty();

void push(uint8_t value);

uint8_t pop();

uint8_t getRPN(char * expression, uint8_t n);

#endif
