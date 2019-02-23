MAX_SMALLBIN_SIZE = 512
MAX_FASTBIN_SIZE = 88


class Chunk:
    size = None
    address = None
    nextChunk = None
    free = True

class HeapState:
    allocatedChunks = []
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

    def get_fast_bin_index(self,size):
        return (size>>3)-2;

    def allocate_from_fastbin(self, size):
        idx = self.get_fast_bin_index(size)
        fb = self.fastbin[idx]
        self.allocatedChunks.append(fb[0])
        fb=fb[1:]
        self.fastbin[idx] = fb


    def allocate_from_smallbin(self):
        pass

    def consolidate(self):
        pass

    def allocate_from_largebin(self):
        pass

    def allocated_from_unsorted(self):
        pass

    def malloc(self, size):
        if (size <= MAX_FASTBIN_SIZE):
            self.allocate_from_fastbin()
        elif (size <= MAX_SMALLBIN_SIZE):
            self.allocate_from_smallbin()
        else:
            self.allocated_from_unsorted()


    def free(self, y):
        pass
