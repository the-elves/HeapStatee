#define NUM_USERS 100000
static int last_user = 0;

typedef struct User {
		char *first_name;
		char *last_name;
		char *house_no;
		char *street;
		char *city_state;
}User;

static User users[NUM_USERS];
void create_user();

void delete_user(int user_no);
