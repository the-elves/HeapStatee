import angr
import logging
from utils.utils import radar_breakpoint, dump_callstack
from datetime import datetime
import hashlib
import os
vl = logging.getLogger('vuln_logger')
class reach_error(angr.SimProcedure):
    def run(self):
        vl.warning("reach error reached")
        print("reach error reached")
        print(dump_callstack(self.state))
        self.dump_testcase()
        exit()

    def dump_testcase(self):
        header_string = '<?xml version="1.0" encoding="UTF-8" standalone="no"?>\n' \
                        '<!DOCTYPE testcase PUBLIC "+//IDN sosy-lab.org//DTD test-format testcase 1.1//EN" "https://sosy-lab.org/test-format/testcase-1.1.dtd">\n'\
                        '<testcase coversError="true">\n'
        close_tag = '</testcase>'
        name = self.project.filename.split("/")[-1]
        with open(f"../GeneratedTestCases/Garuda-{name}-testcase.xml","w") as f:
            f.write(header_string)
            for r in self.state.my_heap.rands:
                input_line = "  <input>" + str(self.state.solver.eval(r))+"</input>\n"
                f.write(input_line)
            f.write(close_tag)
        timestr = str(datetime.now())
        with open(self.project.filename,"rb") as bf:
            bytes = bf.read()
            binaryhash = str(hashlib.sha256(bytes).hexdigest())
        header_string = '<?xml version="1.0" encoding="UTF-8" standalone="no"?>\n' \
                        '<!DOCTYPE test-metadata PUBLIC "+//IDN sosy-lab.org//DTD test-format test-metadata 1.1//EN"' \
                        ' "https://sosy-lab.org/test-format/test-metadata-1.1.dtd">\n' \
                        '<test-metadata>\n' \
                        '  <sourcecodelang>C</sourcecodelang>\n' \
                        '  <producer>GARUDA</producer>\n' \
                        '  <specification>CHECK( init(main()), LTL(G ! call(reach_error())) )</specification>\n' \
                        f'  <programfile>{self.state.project.filename}</programfile>\n' \
                        f'  <programhash>{binaryhash}</programhash>\n' \
                        '  <entryfunction>main</entryfunction>\n' \
                        '  <architecture>64bit</architecture>\n' \
                        f'  <creationtime>{timestr}</creationtime>\n' \
                        '</test-metadata>'
        with open(f"../GeneratedTestCases/Garuda-{name}-metadata.xml", "w") as f:
            f.write(header_string)


class __VERIFIER_error(angr.SimProcedure):
    def run(self):
        vl.warning("__VERIFIER_error reached")
        print("__VERIFIER_error reached")
        # radar_breakpoint()
        exit()
