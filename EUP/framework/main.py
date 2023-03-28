import argparse
import logging
import signal
import time
from itertools import chain

import angr

import detectors, explorers


class TimeoutError(Exception): # So we can limit execution time
    pass

def handle_timeout(signum, frame):
    print("Timed out")
    raise TimeoutError("Timeout")

def run_with_timeout(func, timeout, *args, **kwargs):
    signal.signal(signal.SIGALRM, handle_timeout)

    begin_time = time.time()

    signal.alarm(timeout)
    try:
        result = func(*args, **kwargs)

    except TimeoutError:
        #print(f"{func} timed out")
        result = None
        pass

    finally:
        end_time = time.time()
        total_time = int(end_time - begin_time)
        signal.alarm(0)

    return total_time, result

def test_explorer(explorer: explorers.Explorer, *args):
    
    proj = angr.Project(target)

    heartdetect = detectors.HearbleedDetector()
    heartdetect.attach(proj)

    entry_state = proj.factory.entry_state(args=[target, "4040"])
    exp = explorer(proj, entry_state)
    exp_time, _ = run_with_timeout(exp.go, timeout, *args)

    print(f"{exp.__class__.__name__} ran for {exp_time} seconds and gave stats: {exp.stats()}")
    return exp



def main():

    l = logging.getLogger()
    l.setLevel(logging.ERROR)

    parser = argparse.ArgumentParser("main.py")

    parser.add_argument("-t","--target", type=str, help="target", default="./toybox")
    parser.add_argument("-s","--timeout", type=int, help="number of seconds to run the explorers", default=20)
    parser.add_argument("-n", "--bugs", type=int, help="number of bugs find", default=1)
    parser.add_argument("-e", "--explorer", help="which explorer to use", default="naive")
    parser.add_argument("-o", "--hook-option", type=str, help="hook type to use(useful only when using eup)", default="a")

    args = parser.parse_args()

    timeout = args.timeout
    target = args.target
    num_bugs = args.bugs
    explorer = args.explorer
    hook_type = args.hook_option


    names = {"eup": explorers.EUPExplorer, "naive": explorers.NaiveExplorer}
    begin = 0x4015da
    exp = names[explorer]
    if exp == explorers.EUPExplorer:
        test_explorer(exp, begin, num_bugs, hook_type)
    else:
        test_explorer(exp, num_bugs)
    
if __name__ == "__main__":
    main()
