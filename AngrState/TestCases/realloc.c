#include<stdio.h>
#include<stdlib.h>
int main()
{
  void *p, *q;
  p = malloc(0x40);
  q = realloc(p, 0x20);
  return q;
}
