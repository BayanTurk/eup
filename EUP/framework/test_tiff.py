import logging
import sys
import os

import angr

from explorers import EUPExplorer
from main import run_with_timeout
from sims import getopt_hook
from detectors import SymbolicStrlenDetector
from helpers import print_cs
from helpers import parse_entry_state_json

proj = angr.Project(os.path.abspath("../../libtiff/my_build/bin/tiffcp"), load_options={"auto_load_libs":False})
entry, _ = parse_entry_state_json(proj, "../misc/trace", "../misc/trace")

loop_head = proj.loader.find_symbol("TIFFReadDirectory").rebased_addr

#proj.hook_symbol("getopt", getopt_hook())


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
