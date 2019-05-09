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
    prev_size = None
    address = None
    next_chunk = None
    prev_chunk = None
    free = True
    user_address = None

class HeapState:
    allocated_chunks = []
    fastbin = []
    smallbin = []
    largebin = []
    unsortedbin = []
    lastremainder = None
    top = None
    startAddress = 0

    #returns None if such chunk is not present
    def get_chunk_at_offset(self, ad, of):
        chunk_addr = ad+of;
        return self.get_chunk_by_address(chunk_addr)

    def get_chunk_by_address(self, ad):
        for bin in self.fastbin:
            for ch in bin:
                if ch.address == ad:
                    return ch;
        for bin in self.smallbin:
            for ch in bin:
                if ch.address == ad:
                    return ch;
        for bin in self.largebin:
            for ch in bin:
                if ch.address == ad:
                    return ch;
        for bin in self.unsortedbin:
            for ch in bin:
                if ch.address == ad:
                    return ch;
        return None
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
    def smallbin_index(self, sz):
        if (SMALLBIN_WIDTH == 16):
            return ((sz>>4) + SMALLBIN_CORRECTION)
        else:
            return ((sz>>3) + SMALLBIN_CORRECTION)

    def large_bin_index(self,sz):
        if ((sz >> 6) <= 38):
            return 56 + (sz >> 6)
        elif (( sz >> 9) <= 20):
            return 91 + (sz >> 9)
        elif((sz >> 12) <= 10):
            return 110 + (sz >> 12)
        elif((sz >> 15) <= 4):
            return 119 + (sz >> 15)
        elif((sz >> 18) <= 2):
            return 124 + (sz >> 18)
        else:
            return 126

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
        for bin in self.fastbin:
            for chunk in bin:
                next = self.get_chunk_at_offset(chunk.address, chunk.size)
                new_chunk = Chunk()
                new_chunk.address = chunk.address
                if(next != None):
                    if(next.free):
                        bin.remove(next)
                        size = size + next.size
                prev = self.get_chunk_at_offset(chunk.address, -chunk.prev_size)
                if(prev != None):
                    if prev.free:
                        bin.remove(prev)
                        size = size + prev.size
                        address = prev.address



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
            victim = self.allocate_from_unsorted()
            if(victim != None):
                return victim




    def free(self, y):
        pass
