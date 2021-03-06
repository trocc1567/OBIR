#include <string.h>
#include <stdio.h>

#define MAX_SIZE 15
//Global variables
uint8_t stack[MAX_SIZE];
uint8_t top = 0;

//make stack empty
void makeEmpty()
{
	top = 0;
}

//push value on stack
void push(uint8_t value)
{
	stack[top++] = value;
}

//pop value from stack
uint8_t pop()
{
	return stack[--top];
}

//Calculate RPN for string expression and n variable
uint8_t getRPN(char * expression, uint8_t n)
{
    char * ch;		//pointer to parsing components
    char exp[30];	//string, when input expression is copied
    strcpy(exp, expression);
    makeEmpty();
    //parse first component from expression
    ch = strtok (exp," ");
     while (ch!=NULL)
     {
		 //if component is a number
         if (ch[0]>=48 && ch[0]<=57)
            push(atoi(ch));
         //if component is a n variable   
         else if (ch[0]=='n')
             push(n);
         //if component is a sign
         else
         {
             switch(ch[0])
			{
				case '+':
					push(pop() + pop());
					break;
				case '-':
					push(pop()-pop());
					break;
				case '*':
					push(pop()*pop());
					break;
				case '/':
					push(pop()/pop());
					break;
			}
         }
            //parse new sign
         ch = strtok (NULL, " ");
		}
		return pop();
	}
