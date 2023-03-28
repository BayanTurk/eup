import angr
import os

from detectors import NginxHeartBleedDetector
from explorers import EUPExplorer
from sims import gettime_hook

proj = angr.Project(os.path.abspath("../nginx/build/sbin/nginx"))
entry = proj.factory.entry_state(concrete_fs=True)

det = NginxHeartBleedDetector()
det.attach(proj)

proj.hook_symbol("clock_gettime", gettime_hook())
exp = EUPExplorer(proj, entry)

if __name__ == "__main__":
    exp.go("ngx_event_accept", 1)