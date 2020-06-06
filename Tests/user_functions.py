
UDEBUG = 0
class User_Info:
    ACTIONS = [128, 48, 64, 144]

    def __init__(self, h):
        self.allocation_num = 0
        self.h = h
        self.first_name = None
        self.last_name = None
        self.house_no = None
        self.street = None
        self.city_state = None

    def update_heap(self, n):
        self.h = n

    def create_user(self):
        if UDEBUG == 1:
            print ("Create User")
        if UDEBUG == 3:
            print ("-----------Starting create_user-----------")
        if UDEBUG == 3:
            print("----------------------before------------------------")
            self.h.dump_parsed(UDEBUG)
            print("----------------------after------------------------")
        self.first_name = self.h.malloc(110)
        if UDEBUG == 3:
            print ("malloc returned first name ", self.first_name)
        if UDEBUG == 3:
            print('----------- after firstname-----------------')
            self.h.dump_parsed(UDEBUG)
        self.last_name = self.h.malloc(39)
        if UDEBUG == 3:
            print ("malloc returned last name ", self.last_name)
        if UDEBUG == 3:
            print('----------------------------after lastname----------------')
            self.h.dump_parsed(UDEBUG)
        self.house_no = self.h.malloc(44)
        if UDEBUG == 3:
            print ("malloc returned hno name ", self.house_no)
        if UDEBUG == 3:
            print('----------------------------after hno----------------')
            self.h.dump_parsed(UDEBUG)
        self.street = self.h.malloc(128)
        if UDEBUG == 3:
            print ("malloc returned street name ", self.street)
        if UDEBUG == 3:
            print('----------------------------after street----------------')
            self.h.dump_parsed(UDEBUG)
        self.city_state = self.h.malloc(127)
        if UDEBUG == 3:
            print ("malloc returned city state name ", self.city_state)
        if UDEBUG == 3:
            print('----------------------------after city_state----------------')
            self.h.dump_parsed(UDEBUG)
            print('----------------------------end----------------')
        if UDEBUG == 3:
            print ("-----------------------=create_user finished=-------------------")

    def delete_user(self):
        if UDEBUG == 1:
            print ("Del User")
        if UDEBUG == 3:
            print ("starting delete user")
        if UDEBUG == 3:
            print ("freeing hno", self.house_no)
        self.h.free(self.house_no)
        if UDEBUG == 3:
            self.h.dump_parsed(UDEBUG)
        if UDEBUG == 3:
            print ("freeing st", self.street)
        self.h.free(self.street)
        if UDEBUG == 3:
            self.h.dump_parsed(UDEBUG)
        if UDEBUG == 3:
            print ("freeing cs ", self.city_state)
        self.h.free(self.city_state)
        if UDEBUG == 3:
            self.h.dump_parsed(UDEBUG)
        if UDEBUG == 3:
            print ("freeing ln ", self.last_name)
        self.h.free(self.last_name)
        if UDEBUG == 3:
            self.h.dump_parsed(UDEBUG)
        if UDEBUG == 3:
            print ("freeing fn", self.first_name)
        self.h.free(self.first_name)
        if UDEBUG == 3:
            self.h.dump_parsed(UDEBUG)
        if UDEBUG == 3:
            print ("-----------------------del_user finished-----------------------------")

        