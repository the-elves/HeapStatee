#include<stdio.h>
#include<stdlib.h>
int main()
{
  void *p, *q, *r;
  p = malloc(0x10);
  r = malloc(20);
  q = realloc(p, 0x20);
  return q;
}
