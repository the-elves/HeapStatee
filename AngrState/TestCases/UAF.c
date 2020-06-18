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
  p-> authenticated = 0;
  free(p);
  struct user *admin_user = (struct user *) malloc(sizeof(struct user));
  p->authenticated=1;
  struct user *normal_user = p;
    
}
