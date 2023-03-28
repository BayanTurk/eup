import angr
from sims import *

TLS1_RT_HEARTBEAT = 0x18

class Detector():
    def __init__(self):
        self.hooks = dict()
        self.old_hooks = dict()  # we might need to detach, so attach can maybe in the future store old hooks, but for now....
        
    def attach(self, project): # attach detector to project, this will install hooks and other things like breakpoints
        for symbol, hook in self.hooks.items():
            project.hook_symbol(symbol, hook, replace=True)

    def detach(self, project):
        for symbol, hook in self.hooks.items():
            project.unhook(project.loader.find_symbol(symbol).rebased_addr) # Remove our hooks

        for symbol, hook in self.old_hooks.items():
            project.hook(project.loader.find_symbol(symbol).rebased_addr) # Install old ones
            

class HearbleedDetector(Detector): #This is the detector for heartbleed: Not sure if this is right or not
    def __init__(self):
        super().__init__()
        self.hooks = {"recv":recv_hook(), "send":send_hook()}

class NginxHeartBleedDetector(Detector):
    def __init__(self):
        super().__init__()
        self.hooks = {"dtls1_write_bytes": dtls1_write_bytes_hook()}

class SymbolicStrlenDetector(Detector):
    def __init__(self):
        super().__init__()
        self.hooks = {"strlen": strlen_hook()}

    
