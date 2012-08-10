#
# Cuckoo customer signature
# Purpose: Report the detection of a debugger
#
# Author: Xavier Mertens <xavier@rootshell.be>
# 

from lib.cuckoo.common.abstracts import Signature

class TestDebugger(Signature):
    name = "test_debugger"
    description = "Tries to detect the presence of a debugger"
    severity = 1
    categories = ["generic"]
    authors = ["Xavier Mertens <xavier@rootshell.be>"]
    minimum = "0.4"

    def run(self, results):
        for p in results["behavior"]["processes"]:
            for c in p["calls"]:
                if c["api"].find("IsDebuggerPresent") >= 0:
                    return True       
        return False
