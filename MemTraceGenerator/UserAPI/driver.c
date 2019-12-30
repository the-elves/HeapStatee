#include"api.h"
#include<stdio.h>
#include<stdlib.h>
#include<sys/resource.h>
#define COMMAND_SIZE 100
#define NUM_USERS 100000

int increaseStackLimit()
{
	struct rlimit rl;
	int result = getrlimit(RLIMIT_STACK, &rl);
	if(result == 0)
	{
		rl.rlim_cur = RLIM_INFINITY;
		result = setrlimit(RLIMIT_STACK, &rl);
		if(result == 0)
			return 0;
	}
	printf("Could not change stack limit \n");
	return -1;
}

int main(int argc, char *argv[])
{
	increaseStackLimit();
	User users[NUM_USERS];
	FILE *fp;
	fp = fopen(argv[1], "r");
	char command [COMMAND_SIZE];
	int last_user = 0;
	while( fgets(command, COMMAND_SIZE, fp) != NULL){
			printf("command %s", command);
			if(command[0] == 'f'){
					int free_number = atoi(command+2);
					printf("Freeing user no %d\n", free_number);
					delete_user(users[free_number]);
			}
			else if(command[0] == 'm'){
					printf("Allocating at location %d\n", last_user); 
					create_user(users+last_user, &last_user);
			}
  }
	printf("%p\n", (void *)users[argc].first_name);
}
