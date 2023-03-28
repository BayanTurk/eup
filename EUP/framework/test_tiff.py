import logging
import sys
import os

import angr

from explorers import EUPExplorer
from main import run_with_timeout
from sims import getopt_hook
from detectors import SymbolicStrlenDetector
from helpers import print_cs


proj = angr.Project(os.path.abspath("../libtiff/my_build/bin/tiffcp"), load_options={"auto_load_libs":False})
entry = proj.factory.entry_state(args=["tiffcp", "/tmp/poc", "/tmp/foo"])

loop_head = proj.loader.find_symbol("TIFFReadDirectory").rebased_addr

#proj.hook_symbol("getopt", getopt_hook())

poc_file = open("../poc", "rb")
poc_raw = poc_file.read()
poc_file.read()

poc = angr.SimFile("/tmp/poc", content=poc_raw, concrete=True, writable=False, has_end=True)
out = angr.SimFile("/tmp/foo")
entry.fs.insert("/tmp/poc", poc)
entry.fs.insert("/tmp/foo", out)

logging.getLogger().setLevel("ERROR")
eup = EUPExplorer(proj, entry)

try:
    run_with_timeout(eup.go, 2 * 60, loop_head, 1, "c")
except KeyboardInterrupt:
    pass
finally:
    print(eup.stats())
    """
    for st in eup.sim.active:
        print_cs(st, proj)
    """