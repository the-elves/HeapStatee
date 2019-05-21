from mstate import *

h = HeapState(0x00)

class user_info:

    def create_user(self):
        self.first_name = h.malloc(110)
        self.last_name = h.malloc(39)


    def create_address(self):
        self.house_no = h.malloc(44)
        self.street = h.malloc(128)
        self.city_state = h.malloc(128)


    def deleteUser(self):
        h.free(self.house_no)
        h.free(self.street)
        h.free(self.city_state)
        h.free(self.last_name)
        h.free(self.first_name)
        