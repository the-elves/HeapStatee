#define __USE_LARGEFILE64
#define _LARGEFILE_SOURCE
#define _LARGEFILE64_SOURCE

#include<sys/fcntl.h>
#include<stdio.h>

int main()
{
  struct stat64 buf;
  fstat64(0, &buf);
  printf("%d", buf.st_uid);
}
