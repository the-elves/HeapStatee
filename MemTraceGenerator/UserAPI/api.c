#include<stdio.h>
#include "api.h"
#include <stdlib.h>
extern int last_user;
void create_user(User *u, int *last_user)
{
		u->first_name=(char *)malloc(110);
		printf("firstname address: %llx\n", u->first_name);
		u->last_name=(char *)malloc(39);
		u->house_no=(char *)malloc(44);
		u->street = (char *)malloc(128);
		u->city_state = (char *)malloc(127);
		(*last_user)++;
}

void delete_user(User user)
{
		free(user.house_no);
		free(user.street);
		free(user.city_state);
		free(user.last_name);
		free(user.first_name);
}
