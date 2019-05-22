

class User_Info:

    def __init__(self, h):
        self.h = h
    def create_user(self):
        self.first_name = self.h.malloc(110)
        self.last_name = self.h.malloc(39)
        self.house_no = self.h.malloc(44)
        self.street = self.h.malloc(128)
        self.city_state = self.h.malloc(127)


    def deleteUser(self):
        self.h.free(self.house_no)
        self.h.free(self.street)
        self.h.free(self.city_state)
        self.h.free(self.last_name)
        self.h.free(self.first_name)
        