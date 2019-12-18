
DEBUG = 0
class User_Info:
    ACTIONS = [128, 48, 64, 144]

    def __init__(self, h):
        self.h = h
        self.first_name = None
        self.last_name = None
        self.house_no = None
        self.street = None
        self.city_state = None

    def update_heap(self, n):
        self.h = n

    def create_user(self):
        if DEBUG == 1:
            print ("Create User")
        if DEBUG == 3:
            print ("-----------Starting create_user-----------")
        if DEBUG == 3:
            self.h.dump()
        self.first_name = self.h.malloc(110)
        if DEBUG == 3:
            print ("malloc returned first name ", self.first_name)
        if DEBUG == 3:
            self.h.dump()
        self.last_name = self.h.malloc(39)
        if DEBUG == 3:
            print ("malloc returned last name ", self.last_name)
        if DEBUG == 3:
            self.h.dump()
        self.house_no = self.h.malloc(44)
        if DEBUG == 3:
            print ("malloc returned hno name ", self.house_no)
        if DEBUG == 3:
            self.h.dump()
        self.street = self.h.malloc(128)
        if DEBUG == 3:
            print ("malloc returned street name ", self.street)
        if DEBUG == 3:
            self.h.dump()
        self.city_state = self.h.malloc(127)
        if DEBUG == 3:
            print ("malloc returned city state name ", self.city_state)
        if DEBUG == 3:
            self.h.dump()
        if DEBUG == 3:
            print ("-----------------------=create_user finished=-------------------")

    def delete_user(self):
        if DEBUG == 1:
            print ("Del User")
        if DEBUG == 3:
            print ("starting delete user")
        if DEBUG == 3:
            print ("freeing hno", self.house_no)
        self.h.free(self.house_no)
        if DEBUG == 3:
            self.h.dump()
        if DEBUG == 3:
            print ("freeing st", self.street)
        self.h.free(self.street)
        if DEBUG == 3:
            self.h.dump()
        if DEBUG == 3:
            print ("freeing cs ", self.city_state)
        self.h.free(self.city_state)
        if DEBUG == 3:
            self.h.dump()
        if DEBUG == 3:
            print ("freeing ln ", self.last_name)
        self.h.free(self.last_name)
        if DEBUG == 3:
            self.h.dump()
        if DEBUG == 3:
            print ("freeing fn", self.first_name)
        self.h.free(self.first_name)
        if DEBUG == 3:
            self.h.dump()
        if DEBUG == 3:
            print ("-----------------------del_user finished-----------------------------")

        