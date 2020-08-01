#include<stdio.h>
#include<stdlib.h>
#include<string.h>
int main()
{
    void *p = malloc(32);
    memset(p, 0,50);
//    for(int i = 0; i<50;i++)
//    {
//        *((char *)(p+i)) = '\0';
//    }
}