#include<stdio.h>
#include "api.h"
#include <stdlib.h>
extern int last_user;
void create_user()
{
		users[last_user].first_name=(char *)malloc(110);
		printf("firstname address: %llx\n", users[last_user].first_name);
		users[last_user].last_name=(char *)malloc(39);
		users[last_user].house_no=(char *)malloc(44);
		users[last_user].street = (char *)malloc(128);
		users[last_user].city_state = (char *)malloc(127);
		last_user++;
}

void delete_user(int user_no)
{
		printf("Freeing user %d\n", user_no);
		free(users[user_no].house_no);
		free(users[user_no].street);
		free(users[user_no].city_state);
		free(users[user_no].last_name);
		free(users[user_no].first_name);
}
