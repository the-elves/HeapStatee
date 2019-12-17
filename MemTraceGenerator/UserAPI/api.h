typedef struct User {
		char *first_name;
		char *last_name;
		char *house_no;
		char *street;
		char *city_state;
}User;

User create_user();

void delete_user(User user);
