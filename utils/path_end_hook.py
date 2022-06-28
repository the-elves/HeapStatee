from fileinput import filename


class PathEndHook:
    def __init__(self) -> None:
        pass

    def run(self):
        raise ("PathEndHook not defined")

class DFSCoveragePathEndHook(PathEndHook):
    def __init__(self, filename) -> None:
        super().__init__()
        self.filename = filename
        self.path_end = "+pathend+\n"

    def run(self):
        with open(self.filename, 'a+') as f:
            f.write(self.path_end)