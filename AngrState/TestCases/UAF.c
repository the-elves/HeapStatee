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
  int result;
  p->authenticated = 0;
  printf("(from program)First malloc: %p\n", p);
  printf("(from program)freeing %p\n", p);
  free(p);
  result = p->authenticated;
  printf("(from program)using after free %d\n", result);

  /* p->authenticated=1; */

}

