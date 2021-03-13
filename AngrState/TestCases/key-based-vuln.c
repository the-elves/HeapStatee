#include<stdio.h>
#include<stdlib.h>
int main(int argc, char *argv[])
{
  char *fn = argv[1];
  FILE *fp = fopen(fn, "r");
  char *v = (char *)malloc(32);
  char p;
  int i=0;
  int sum = 0;
  while((p = fgetc(fp)) != EOF){
    printf("%c", p);
    sum = sum+p;
    if(sum%7==0){
      v[i++] = p;
      sum=0;
    }
  }
  free(v);
}
