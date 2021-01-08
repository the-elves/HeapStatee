#include<stdio.h>
#include<stdlib.h>
int main(int argc, char *argv[])
{
  char *fn = argv[1];
  FILE *fp = fopen(fn, "r");
  char *v = (char *)malloc(32);
  char p;
  int i=0;
  while((p = fgetc(fp)) == 'P'){
    printf("%c", p);
    v[i++] = p;
  }
  free(v);
}
