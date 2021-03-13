/*overflow triggered only on specific value*/

#include<stdio.h>
#include<stdlib.h>
int main(int argc, char *argv[])
{
  char *magic = "abcdefghabcdefghabcdefghabcdefghabcdefgh";
  char *magic_ptr = magic;
  char *file_name = argv[1];
  FILE *fp = fopen(file_name, "r");
  char *v = (char *)malloc(32);
  char p;
  int i=0;
  while((p = fgetc(fp)) == *magic_ptr){
    printf("%c", p);
    magic_ptr++;
    v[i++] = p;
  }
  free(v);
}
