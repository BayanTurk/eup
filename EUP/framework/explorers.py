from collections import defaultdict

import angr
import detectors

from helpers import flatten, hash_state


class Explorer():
    def __init__(self, project: angr.Project, state: angr.sim_state.SimState) -> None:
        self.project = project
        self.sim = project.factory.simgr(state)
        self.buggy_states = {} #We (mostly) don't care about instances of the same bug
        self.hooks_addrs = [] #In the future we may want to store old hooks?
    
    def stats(self): # Here we can collect all the statistics we want so we can perform comparisons
        callstack_unique = set()
        states = [x for x in self.sim.stashes.values()]
        bblocks = set()
        for st in flatten(states):
            callstack_unique.add(hash_state(st))
            bblocks.update(st.history.bbl_addrs)
        return {"Unique blocks explored": len(bblocks), "Number of (unique)buggy states": len(set(self.buggy_states)), "Number of unique states(based on call stack)":len(callstack_unique)}   
    
    def go(self, num_buggy):
        raise NotImplementedError("Use one of the subclasses")

class NaiveExplorer(Explorer):
    def go(self, num_bugs): 
        while len(self.buggy_states) < num_bugs:
            try:
                self.sim.step()
            except detectors.BugFoundError as e:
                self.buggy_states[hash_state(e.state)] = e.state
                continue
    
    def __init__(self, project: angr.Project, state: angr.sim_state.SimState) -> None:
        super().__init__(project, state)
        
class EUPExplorer(Explorer):
    
    @staticmethod
    def option_a_hook(state: angr.sim_state.SimState):
        for x in state.solver.constraints:
            state.solver.append(x == state.solver.eval(x))
        state.solver.simplify()   

    @staticmethod
    def option_c_hook(state: angr.sim_state.SimState):
        print(state.solver.constraints)
        print(state.addr)
        state.solver.constraints.clear()

    @staticmethod
    def no_hook(state):                 
        pass

       
    def go(self, loop_head, num_bugs, hook_type="a"):

        #We'll have to find the loophead automatically eventually
        if type(loop_head) == str:
            self.project.hook_symbol(loop_head, self.hook_types[hook_type])
        else:
            self.project.hook(loop_head, self.hook_types[hook_type])
        while len(self.buggy_states) < num_bugs:
            try:
                self.sim.step()
            except detectors.BugFoundError as e:
                self.buggy_states[hash_state(e.state)] = e.state
                break

    def __init__(self, project: angr.Project, state: angr.sim_state.SimState) -> None:
        super().__init__(project, state)
        self.hook_types = defaultdict(lambda: self.__class__.no_hook,a=self.__class__.option_a_hook, c=self.__class__.option_c_hook)
