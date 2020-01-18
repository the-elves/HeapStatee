import sys
from Colors import bcolors
align_of_long_double = 16
SIZE_SZ = 8
MALLOC_ALLIGNMENT = align_of_long_double if 2 * SIZE_SZ < align_of_long_double else 2 * SIZE_SZ
N_BINS = 128
N_SMALL_BINS = 64
SMALLBIN_WIDTH = MALLOC_ALLIGNMENT
SMALLBIN_CORRECTION = 1 if (MALLOC_ALLIGNMENT > 2 *SIZE_SZ ) else 0
MIN_LARGE_SIZE = ((N_SMALL_BINS - SMALLBIN_CORRECTION) * SMALLBIN_WIDTH)
STARTING_ADDRESS = 0
STARTING_SIZE = 0
MALLOC_ALIGN_MASK = MALLOC_ALLIGNMENT - 1
MIN_SIZE = (32 + MALLOC_ALIGN_MASK) & ~ MALLOC_ALIGN_MASK
PREV_INUSE = 1
MAX_ITERATIONS = 10000
MAX_FASTBIN_SIZE = 64 * SIZE_SZ / 4
FASTBIN_CONSOLIDATION_THRESHOLD = 65536
DEBUG = True
MAX_SMALLBIN_SIZE = ((N_SMALL_BINS - SMALLBIN_CORRECTION) * SMALLBIN_WIDTH)
class Chunk:
    id = 0
    def __init__(self):
        Chunk.id = Chunk.id + 1
        self.size = None
        self.prev_size = 0
        self.address = None
        self.fd = None
        self.bin = None
        self.bk = None
        self.free = True
        self.is_mmapped = False
        self.user_address = None
        self.is_top = False
        self.bin = None


    # def __eq__(self, other):
    #     if self.size == other.size and self.address == other.address and \
    #        self.free == other.free:
    #         return True
    #     return False


    def dump_chunk(self):
        print ("[" , \
              "address = ",self.address, \
              "size = ",self.size, \
              "free = ", self.free, \
              "prev_size = ", self.prev_size, \
              "end address = ", self.address+self.size, \
              "]")


class HeapState:

    #returns None if such chunk is not present
    def get_chunk_at_offset(self, ad, of):
        chunk_addr = ad+of
        return self.get_chunk_by_address(chunk_addr)

    def get_chunk_by_address(self, ad):
        for bin in self.fastbin:
            for ch in bin:
                if ch.address == ad:
                    return ch
        for bin in self.smallbin:
            for ch in bin:
                if ch.address == ad:
                    return ch
        for bin in self.largebin:
            for ch in bin:
                if ch.address == ad:
                    return ch
        for ch in self.unsortedbin:
            if ch.address == ad:
                return ch
        for ch in self.allocated_chunks:
            if ch.address == ad:
                return ch
        if self.top.address == ad:
            return self.top
        return None

    def __init__(self, startAddress):
        self.allocated_chunks = []
        self.fastbin = []
        self.smallbin = []
        self.largebin = []
        self.unsortedbin = []
        self.lastremainder = None
        self.startAddress = startAddress
        for i in range(10):
            self.fastbin.append([])
        for i in range(64):
            self.smallbin.append([])
        self.top = Chunk()
        self.top.size = STARTING_SIZE
        self.top.address = startAddress
        self.top.is_top = True

    #fast bin helper routines
    def get_fast_bin_index(self,size):
        return ((size>>(4 if SIZE_SZ == 8 else 3)) -2)

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

    def allocate_from_smallbin(self, sz):
        idx = self.smallbin_index(sz)
        bin = self.smallbin[idx]
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
                bin.remove(chunk)
                address = chunk.address
                size = chunk.size
                new_prev_size = chunk.prev_size
                prev = self.get_chunk_at_offset(chunk.address, -chunk.prev_size)
                # add_to_unsorted = False
                if(chunk.address != 0 and prev == None):
                    print ("prev not found error")
                    sys.exit("prev is none")
                if(chunk.address != 0):
                    if (prev.free):
                        # TODO need unlink macro here
                        # add_to_unsorted = True
                        prev_bin = prev.bin
                        prev_bin.remove(prev)
                        size = chunk.size + prev.size
                        address = prev.address
                        new_prev_size = prev.prev_size
                next = self.get_chunk_at_offset(chunk.address, chunk.size)
                # if next is None:
                #     exit("Next none in cosolidate")
                if next.address == self.top.address:
                    # add_to_unsorted = False
                    size = size + next.size
                    self.top.address = address
                    self.top.size = size
                    self.top.prev_size = new_prev_size
                    self.top.free = True
                else :
                    if next.free:
                        #TODO need unlink macro here
                        current_bin = next.bin
                        current_bin.remove(next)
                        size = size + next.size
                    new_chunk = Chunk()
                    new_chunk.address = address
                    new_chunk.size = size
                    new_chunk.free = True
                    new_chunk.prev_size = new_prev_size
                    new_chunk.bin = self.unsortedbin
                    self.set_next_size(new_chunk, new_chunk.size)
                    self.unsortedbin.insert(0, new_chunk)





    def allocate_from_largebin(self):
        pass

    def allocate_from_unsorted(self):
        pass

    def request2size(self, req):
        if ((req + SIZE_SZ + MALLOC_ALIGN_MASK) < MIN_SIZE):
            return MIN_SIZE
        else:
            return (req + SIZE_SZ + MALLOC_ALIGN_MASK) & ~MALLOC_ALIGN_MASK

    def set_next_size(self, ch, sz):
        next_chunk = self.get_chunk_at_offset(ch.address, ch.size)
        next_chunk.prev_size = sz

    ############### Malloc  ##################
    def malloc(self, bytes):
        nb = self.request2size(bytes)
        if (nb <= MAX_FASTBIN_SIZE):
            victim = self.allocate_from_fastbin(nb)
            if (victim != None):
                victim.free = False
                return victim.address
        elif (nb <= MIN_LARGE_SIZE):
            victim = self.allocate_from_smallbin(nb)
            if (victim != None):
                victim.free = False
                return victim.address
        else:
            self.consolidate()
        while True:
            iteration = 0
            while len(self.unsortedbin) !=0:
                victim = self.unsortedbin[-1]
                size = victim.size
                #todo add checks : malloc(): memory corruption
                #XXX POTENTIAL ERROR not used. Previous element of list used
                if (nb <= MAX_SMALLBIN_SIZE and\
                        len(self.unsortedbin) == 1 and\
                        victim == self.lastremainder and\
                        size > nb+MIN_SIZE):
                    remainder_size = size-nb
                    remainder = Chunk()
                    remainder.free = True
                    remainder.size  = remainder_size
                    remainder.address = victim.address + nb
                    remainder.prev_size = nb
                    self.set_next_size(remainder, remainder.size)
                    self.unsortedbin.remove(self.unsortedbin[-1])
                    remainder.bin=self.unsortedbin
                    self.unsortedbin.insert(0, remainder)
                    self.lastremainder = remainder
                    #TODO handle large bins
                    #TODO handle main arena
                    victim.size = nb
                    #TODO   handle bk and fd
                    self.allocated_chunks.append(victim)
                    victim.free = False
                    return victim.address


                self.unsortedbin.remove(self.unsortedbin[-1])
                if size == nb:
                    # XXX this chunks inuse set instead of next chunks prev_inuse
                    victim.free=False
                    #TODO add checks : check_malloced_chunk(av, victim, nb)
                    self.allocated_chunks.append(victim)
                    victim.free = False
                    return victim.address

                #place chunk in bins
                if size <= MAX_SMALLBIN_SIZE:
                    victim_idx = self.smallbin_index(size)
                    bin = self.smallbin[victim_idx]
                    bin.append(victim)
                    victim.bin = bin

                iteration = iteration + 1
                if(iteration > MAX_ITERATIONS):
                    break

            idx = self.smallbin_index(nb)
            while(idx < len(self.smallbin)):
                bin = self.smallbin[idx]
                if(len(bin) == 0):
                    idx+=1
                    continue
                ch = bin[-1]
                size = ch.size
                remainder_size = size-nb
                bin.remove(ch)
                if remainder_size < MIN_SIZE:
                    ch.free = False
                else:
                    rem_add = ch.address + nb
                    new_chunk = Chunk()
                    new_chunk.address = rem_add
                    new_chunk.size = remainder_size
                    new_chunk.free = True
                    new_chunk.prev_size = nb
                    new_chunk.bin =self.unsortedbin
                    self.set_next_size(new_chunk, new_chunk.size)
                    self.unsortedbin.insert(0,new_chunk)
                    self.lastremainder = new_chunk
                    ch.size = nb
                ch.free = False
                self.allocated_chunks.append(ch)
                return ch.address
            #TODO handle largebin



            #use top
            victim = self.top
            size = victim.size
            if(size>nb+MIN_SIZE):
                remainder_size = size - nb
                remainder = Chunk()
                remainder.size = remainder_size
                remainder.address = victim.address+nb
                remainder.free = True
                remainder.prev_size = nb
                self.top = remainder
                self.top.is_top = True
                victim.size = nb
                victim.free = False
                self.allocated_chunks.append(victim)
                return victim.address

            #sysmalloc
            #TODO handle properly
            self.top.size = self.top.size + 0x21000


    def free(self, p):
        #TODO add security checks
        p_chunk = None
        for c in self.allocated_chunks:
            if p == c.address:
                p_chunk = c
                break

        if p_chunk is None:
            print ("freed chunk not found in allocated chunks")
            sys.exit(0)
        self.allocated_chunks.remove(p_chunk)
        size = p_chunk.size
        address = p_chunk.address
        if p_chunk.size <= MAX_FASTBIN_SIZE:
            #TODO add checks: "free(): invalid next size (fast)"
            idx = self.get_fast_bin_index(p_chunk.size)
            fb = self.fastbin[idx]
            fb = [p_chunk]+fb
            self.fastbin[idx]= fb
            p_chunk.bin = fb
            #XXX POSSIBLE ERROR: NEXT AND PREVIOUS NOT UPDATED, INHERENTLY MAINTAINED BY THE LIST
            #TODO add checks : double free or corruption (fasttop)
            #TODO MULTIPLE THREADS
            #TODO add checks : invalid fastbin entry (free)
        elif not p_chunk.is_mmapped:
            #TODO: multiple thereads
            next_chunk = self.get_chunk_at_offset(p_chunk.address, p_chunk.size)
            #TODO add checks : double free or corruption (top), (out), (!prev)
            nextsize = next_chunk.size
            #TODO add checks : free(): invalid next size (normal)
            prev_chunk = None
            new_prev_size = p_chunk.prev_size
            if p_chunk.address != 0:
                prev_chunk = self.get_chunk_at_offset(p_chunk.address, -p_chunk.prev_size)
                #XXX probable error : previous inuse checked hackily
                # instead of checking current chunks prev_inuse and we are checking if the chunk is present in free lists
                if prev_chunk == None:
                    print ("prev_chunk is none in free")
                    sys.exit("prev_chunk is none in free")
                if prev_chunk.free:
                    prev_chunk_bin = prev_chunk.bin
                    prev_idx = prev_chunk_bin.index(prev_chunk)
                    prev_size = prev_chunk.size
                    new_prev_size = prev_chunk.prev_size
                    size = size + prev_size
                    address = prev_chunk.address
                    del(prev_chunk_bin[prev_idx])

            # XXX probable error : previous inuse checked hackily
            # instead of checking current chunks next_inuse and we are checking if the chunk is present in free lists

            if(self.top.address != next_chunk.address):
                if next_chunk.free:
                    next_idx = next_chunk.bin.index(next_chunk)
                    size = size + next_chunk.size
                    del(next_chunk.bin[next_idx])
                #XXX POSSIBLE ERROR : instead of clearing prev inuse bit of nxt chunk
                #    nothing is done
                #TODO add checks : free(): corrupted unsorted chunks
                #XXX POSSIBLE ERROR : fw and bk not used inherently maintained by list

                new_chunk = Chunk()
                new_chunk.size = size
                new_chunk.address = address
                new_chunk.free = True
                new_chunk.bin = self.unsortedbin
                new_chunk.is_mmapped = False
                new_chunk.prev_size = new_prev_size
                self.set_next_size(new_chunk, new_chunk.size)
                self.unsortedbin.insert(0, new_chunk)
            else:
                size = size + nextsize
                self.top.size = size
                self.top.address = address
                self.top.prev_size = new_prev_size

            if(size > FASTBIN_CONSOLIDATION_THRESHOLD):
                self.consolidate()

        #TODO handle unmap_chunk

    def print_fastbins(self):
        i=0
        for bin in self.fastbin:
            if len(bin) == 0:
                continue
            print("bin ", i,"->")
            i += 1
            for c in bin:
                c.dump_chunk()
    def print_smallbins(self):
        for bin in self.smallbin:
            if len(bin) == 0:
                continue
            print("bin ", self.smallbin.index(bin),"->")
            for c in bin:
                c.dump_chunk()

    def print_unsortedbin(self):
        for c in self.unsortedbin:
            c.dump_chunk()

    def check_distance(self, sz, sz2,  dist):
        size1 = self.request2size(sz)
        size2 = self.request2size(sz2)
        for c in self.allocated_chunks:
            if(c.size == size1):
                for d in self.allocated_chunks:
                    if d.size == size2:
                        if abs(d.address - c.address) == dist:
                            return (c.address, d.address)

    def check_range(self, sz, sz2, low, high):
        size1 = self.request2size(sz)
        size2 = self.request2size(sz2)
        for c in self.allocated_chunks:
            if (c.size == size1):
                for d in self.allocated_chunks:
                    if d.size == size2:
                        dist = abs(d.address - c.address)
                        if dist >= low and dist<high:
                            return (c.address, d.address)

        return None
    def dump(self):
        print ("\n"+bcolors.RED+"[+] printing fastbins")
        self.print_fastbins()
        print ("\n[+]"+bcolors.BLUE+" printing smallbins")
        self.print_smallbins()
        print ("\n[+]"+bcolors.PINK+bcolors.BOLD+" Printing unsorted bins")
        self.print_unsortedbin()
        print ("\n[+] printing top chunk")
        self.top.dump_chunk()
        print ("\n[+] "+bcolors.ENDC+"printing allocated chunk")
        for c in self.allocated_chunks:
            c.dump_chunk()



