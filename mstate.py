MAX_SMALLBIN_SIZE = 512
MAX_FASTBIN_SIZE = 88
SIZE_OF = 4
MALLOC_ALLIGNMENT = 4
N_BINS = 128
N_SMALL_BINS = 64
SMALLBIN_WIDTH = MALLOC_ALLIGNMENT
SMALLBIN_CORRECTION = (MALLOC_ALLIGNMENT > 2*SIZE_OF)
MIN_LARGE_SIZE = ((N_SMALL_BINS - SMALLBIN_CORRECTION) * SMALLBIN_WIDTH)



class Chunk:
    size = None
    address = None
    next_chunk = None
    prev_chunk = None
    free = True


class HeapState:
    allocated_chunks = []
    fastbin = []
    smallbin = []
    largebin = []
    unsortedbin = []
    lastremainder = None
    top = None
    startAddress = 0

    def __init__(self, startAddress):
        self.startAddress = startAddress
        top = startAddress;
        for i in range(10):
            self.fastbin[i] = []
        for i in range(64) :
            self.smallbin[i] = []

#fast bin helper routines
    def get_fast_bin_index(self,size):
        return (size>>3)-2;

    def allocate_from_fastbin(self, size):
        idx = self.get_fast_bin_index(size)
        fb = self.fastbin[idx]
        if (len(fb) == 0):
            return None
        victim = fb[0]
        self.allocated_chunks.append(victim)
        fb=fb[1:]
        self.fastbin[idx] = fb
        return victim


#samll bin helper routines
    def smallbin_index(self, size):
        if (SMALLBIN_WIDTH == 16):
            return ((size>>4) + SMALLBIN_CORRECTION)
        else:
            return ((size>>3) + SMALLBIN_CORRECTION)


    def allocate_from_smallbin(self):
        idx = self.smallbin_index()
        if (len(bin) == 0):
            return None
        bin = self.smallbin[idx]

        victim = bin [-1]

        #TODO: Add checks
        #sec check
        #victim.next_chunk = bin[0].address

        self.allocated_chunks.append(victim)
        #remove
        bin = bin[:len(bin) - 2]
        self.smallbin[idx] = bin
        return victim


    def rebin_unsorted_chunks(self):
        pass

    def try_last_remainder(self):
        pass

    def consolidate(self):
        pass

    def allocate_from_largebin(self):

        pass

    def allocate_from_unsorted(self):
        pass


    ############### Malloc  ##################
    def malloc(self, size):
        if (size <= MAX_FASTBIN_SIZE):
            victim = self.allocate_from_fastbin()
            if (victim != None):
                return victim
        elif (size <= MIN_LARGE_SIZE):
            victim = self.allocate_from_smallbin()
            if (victim != None):
                return victim
        else:

            self.consolidate()
            self.rebin_unsorted_chunks()
            self.allocate_from_unsorted()
            


    def free(self, y):
        pass
