struct person
  {
    char *name;
    int age;
  };
  int main(int argc, char *argv[])
  {
    int len;
    char buffer[BUFFER_SIZE];
    struct person p1;
    printf("Enter first name: ");
    scanf("%s", buffer);
    len = strlen(buffer);
    p1.name = (char *)malloc(len);
    strcpy(p1.name, buffer);
  }