#include"api.h"
#include<stdio.h>
#include<stdlib.h>
#define COMMAND_SIZE 100
int main(int argc, char *argv[])
{
	getchar();
	FILE *fp;
	fp = fopen(argv[1], "r");
	char command [COMMAND_SIZE];
	while( fgets(command, COMMAND_SIZE, fp) != NULL){
	  getchar();
			printf("command %s", command);
			if(command[0] == 'f'){
					int free_number = atoi(command+2);
					delete_user(free_number);
			}
			else if(command[0] == 'm'){
					create_user();
			}
  }
	printf("%p", (void *)users[argc].first_name);
	printf("hello");
}
