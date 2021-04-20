import angr

class strrchr(angr.SimProcedure):
    def run(string, char):
        s = self.state
        
        
