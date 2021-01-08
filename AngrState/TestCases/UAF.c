#include<stdio.h>
#include<stdlib.h>

struct user
{
  char *name;
  int authenticated;
};

int main(int argc, char *argv[])
{
  struct user *p = (struct user*)malloc(sizeof(struct user));
  p->authenticated = 0;
  printf("(from program)First malloc: %p\n", p);
  printf("(from program)freeing %p\n", p);
  free(p);
  printf("(from program)causing write after free\n");
  p->authenticated = 1;
  printf("(from program)causing write after free%d\n", p->authenticated);
  /* p->authenticated=1; */

}

