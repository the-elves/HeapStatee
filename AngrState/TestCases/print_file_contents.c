#include<stdio.h>
int main(int argc, char *argv[])
{
  FILE *fp = fopen(argv[1], "r");
  char c;
  while(1)
  {
    c=fgetc(fp);
    if(c == -1){
      break;
    }
    printf("%c", c);
  }
}
	
