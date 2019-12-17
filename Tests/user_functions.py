
DEBUG=False
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
        if DEBUG:
            print ("-----------Starting create_user-----------")
        if DEBUG:
            self.h.dump()
        self.first_name = self.h.malloc(110)
        if DEBUG:
            print "malloc returned first name ", self.first_name
        if DEBUG:
            self.h.dump()
        self.last_name = self.h.malloc(39)
        if DEBUG:
            print "malloc returned last name ", self.last_name
        if DEBUG:
            self.h.dump()
        self.house_no = self.h.malloc(44)
        if DEBUG:
            print "malloc returned hno name ", self.house_no
        if DEBUG:
            self.h.dump()
        self.street = self.h.malloc(128)
        if DEBUG:
            print "malloc returned street name ", self.street
        if DEBUG:
            self.h.dump()
        self.city_state = self.h.malloc(127)
        if DEBUG:
            print "malloc returned city state name ", self.city_state
        if DEBUG:
            self.h.dump()
        if DEBUG:
            print "-----------------------=create_user finished=-------------------"

    def delete_user(self):
        if DEBUG:
            print "starting delete user"
        if DEBUG:
            print "freeing hno", self.house_no
        self.h.free(self.house_no)
        if DEBUG:
            self.h.dump()
        if DEBUG:
            print "freeing st", self.street
        self.h.free(self.street)
        if DEBUG:
            self.h.dump()
        if DEBUG:
            print "freeing cs ", self.city_state
        self.h.free(self.city_state)
        if DEBUG:
            self.h.dump()
        if DEBUG:
            print "freeing ln ", self.last_name
        self.h.free(self.last_name)
        if DEBUG:
            self.h.dump()
        if DEBUG:
            print "freeing fn", self.first_name
        self.h.free(self.first_name)
        if DEBUG:
            self.h.dump()
        if DEBUG:
            print "-----------------------del_user finished-----------------------------"

        