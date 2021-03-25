#include<stdio.h>
#include<stdlib.h>
int main()
{
  void *p; 
  return posix_memalign(&p, 64, 128);
}
