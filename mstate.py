MAX_SMALLBIN_SIZE = 512
MAX_FASTBIN_SIZE = 88
SIZE_OF = 4
MALLOC_ALLIGNMENT = 4
N_BINS = 128
N_SMALL_BINS = 64
SMALLBIN_WIDTH = MALLOC_ALLIGNMENT
SMALLBIN_CORRECTION = (MALLOC_ALLIGNMENT > 2*SIZE_OF)
MIN_LARGE_SIZE = ((N_SMALL_BINS - SMALLBIN_CORRECTION) * SMALLBIN_WIDTH)
STARTING_ADDRESS = 0x00000000
STARTING_SIZE = 4096
MALLOC_ALIGN_MASK = MALLOC_ALLIGNMENT - 1
MIN_SIZE = (32 + MALLOC_ALIGN_MASK) & ~ MALLOC_ALIGN_MASK
PREV_INUSE = 1
MAX_ITERATIONS = 10000

class Chunk:
    size = None
    prev_size = None
    address = None
    fd = None
    bin = None
    bk = None
    free = True
    is_mmapped = False
    user_address = None
    is_top = False
    bin = None

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
    def get_free_chunk_at_offset(self, ad, of):
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
        top = Chunk
        top.size = STARTING_SIZE
        top.address = STARTING_ADDRESS
        top.is_top = True

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
        #victim.fd = bin[0].address

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
                address = chunk.address
                size = chunk.size
                prev = self.get_free_chunk_at_offset(chunk.address, -chunk.prev_size)
                add_to_unsorted = True
                if (prev != None):
                    if prev.free:
                        # TODO need unlink macro here
                        bin.remove(prev)
                        size = chunk.size + prev.size
                        address = prev.address
                next = self.get_free_chunk_at_offset(chunk.address, chunk.size)
                if (next != None):
                    if next.is_top:
                        add_to_unsorted = False
                        next.address = address
                        next.size = next.size + size
                    else:
                        if(next.free):
                            #TODO need unlink macro here
                            bin.remove(next)
                            size = size + next.size
                if add_to_unsorted:
                    bin.remove(chunk)
                    new_chunk = Chunk
                    new_chunk.address = address
                    new_chunk.size =  size
                    self.unsortedbin.append(new_chunk)


    def allocate_from_largebin(self):
        pass

    def allocate_from_unsorted(self):

        pass


    ############### Malloc  ##################
    def malloc(self, nb):
        if (nb <= MAX_FASTBIN_SIZE):
            victim = self.allocate_from_fastbin()
            if (victim != None):
                self.allocated_chunks.append(victim)
                return victim
        elif (nb <= MIN_LARGE_SIZE):
            victim = self.allocate_from_smallbin()
            if (victim != None):
                self.allocated_chunks.append(victim)
                return victim
        self.consolidate()
        while(True):
            while(len(self.unsortedbin) !=0):
                victim = self.unsortedbin[-1]
                size = victim.size
                #todo add checks : malloc(): memory corruptio
                bck = victim.bk
                if (nb <= MAX_SMALLBIN_SIZE and\
                        self.unsortedbin[0] == bck and\
                        victim == self.lastremainder and\
                        size > nb+MIN_SIZE):
                    remainder_size = size-nb
                    remainder = Chunk
                    remainder.size  = remainder_size
                    remainder.address = victim.address + nb
                    del self.unsortedbin[0]
                    self.unsortedbin[0] = remainder
                    self.lastremainder = remainder
                    #TODO handle large bins
                    #TODO handle main arena
                    victim.size = size | PREV_INUSE
                    #TODO handle bk and fd
                    self.allocated_chunks.append(victim)
                    return victim
                del(self.unsortedbin[-1])
                if size == nb:
                    # XXX this chunks inuse set instead of next chunks prev_inuse
                    victim.free=False
                    #TODO add checks : check_malloced_chunk(av, victim, nb);
                    self.allocated_chunks.append(victim)
                    return victim

                #place chunk in bins
                if size <= MAX_SMALLBIN_SIZE:
                    victim_idx = self.smallbin_index(size)
                    bin = self.smallbin[victim_idx]
                    bin.append(victim)
                    victim.bin = bin
                iteration = iteration + 1
                if(iteration > MAX_ITERATIONS):
                    break;

                #TODO handle largebin

                #use top
                victim = self.top
                size = victim.size
                if(size>nb+MIN_SIZE):
                    remainder_size = size - nb
                    remainder = Chunk
                    remainder.size = remainder
                    remainder.address = victim.address+nb
                    remainder.free = True
                    self.top = remainder
                    victim.size = nb
                    victim.free = False
                    self.allocated_chunks.append(victim)
                    return victim

                #sysmalloc
                self.top.size = self.top.size + 0x21000






        self.rebin_unsorted_chunks()
        victim = self.allocate_from_unsorted()
        if(victim != None):

            return victim




    def free(self, p):
        #TODO add security checks

        for c in self.allocated_chunks:
            if p == c.address:
                p_chunk = c
            size = p_chunk.size
        if p_chunk.size < MAX_FASTBIN_SIZE:
            #TODO add checks: "free(): invalid next size (fast)"
            idx = self.get_fast_bin_index(p_chunk.size)
            fb = self.fastbin[idx]
            p_chunk.free = True
            fb = [p_chunk]+fb
            p_chunk.bin = fb
            #XXX POSSIBLE ERROR: NEXT AND PREVIOUS NOT UPDATED, INHERENTLY MAINTAINED BY THE LIST
            #TODO add checks : double free or corruption (fasttop)
            #TODO MULTIPLE THREADS
            #TODO add checks : invalid fastbin entry (free)
        if not p_chunk.is_mmapped:
            #TODO: multiple thereads
            next_chunk = self.get_free_chunk_at_offset(p_chunk.address, p_chunk.size)
            #TODO add checks : double free or corruption (top), (out), (!prev)
            nextsize = next_chunk.size
            #TODO add checks : free(): invalid next size (normal)
            prev_chunk = self.get_free_chunk_at_offset(p_chunk.address, p_chunk.address - p_chunk.prev_size )
            #XXX probable error : previous inuse checked hackily
            # instead of checking current chunks prev_inuse and we are checking if the chunk is present in free lists
            if prev_chunk != None:
                prev_chunk_bin = prev_chunk.bin
                prev_idx = prev_chunk_bin.index(prev_chunk)
                prev_size = prev_chunk.size
                size = size + prev_size
                address = prev_chunk.address
                del(prev_chunk_bin[prev_idx])
                





