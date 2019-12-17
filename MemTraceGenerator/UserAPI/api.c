#include "api.h"
#include <stdlib.h>
User create_user()
{
		User u;
		u.first_name=(char *)malloc(110);
		u.last_name=(char *)malloc(39);
		u.house_no=(char *)malloc(44);
		u.street = (char *)malloc(128);
		u.city_state = (char *)malloc(127);
		return u;
}

void delete_user(User u)
{
		free(u.house_no);
		free(u.street);
		free(u.city_state);
		free(u.last_name);
		free(u.first_name);
}
