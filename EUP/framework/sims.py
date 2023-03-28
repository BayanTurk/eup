import time

import angr

recv = angr.SIM_PROCEDURES["posix"]["recv"]
send = angr.SIM_PROCEDURES["posix"]["send"]
clock_gettime = angr.SIM_PROCEDURES["posix"]["clock_gettime"] 
strlen = angr.SIM_PROCEDURES["libc"]["strlen"]
simexit = angr.procedures.libc.exit.exit

class BugFoundError(Exception): # So we can stop the simulation manager and store the offending state. Might need to move it to the detector?
    def __init__(self, state, message="bug_found"):
        self.state = state
        self.message = message
        
    def __str__(self):
        return str(str.state) 

class recv_hook():
    def run(self):
        pass

class send_hook():
    def run(self):
        pass


class quit_hook(simexit):
    def run(self, *args):
        super().run(0)
        

class strlen_hook(strlen):
    def run(self, string):
        print(string)
    
class getopt_hook(angr.sim_procedure.SimProcedure):
    def run(self, *args):
        #we don't need getopt
        return -1


class gettime_hook(clock_gettime):
    #This hook is to just change the clock_id to CLOCK_REALTIME since they are roughly the same
    def run(self: angr.sim_procedure.SimProcedure, clockid, tp):
        if self.state.solver.is_true(tp == 0):
            return -1
        
        flt = time.time()
        
        result = {
            "tv_sec": int(flt),
            "tv_nsec": int(flt * 1000000000)
        }

        self.state.mem[tp].struct.timespec = result
        return 0

class recv_hook(recv):
    def run(self: angr.sim_procedure.SimProcedure, fd, dst, length, flags):
        max_len = self.state.solver.max(length)
        #print(f"recv: {max_len}")

        self.state.globals["recv_len"] = max_len

        print(self.state.posix.get_fd(fd))

        a = super().run(fd, dst, length, flags)
        return a


class send_hook(send):
    def run(self, fd, dst, length, flags):
        max_len = self.state.solver.max(length)
        #print(f"send: {max_len}")

        self.state.globals["send_len"] = max_len

        if self.state.globals["recv_len"] < self.state.globals["send_len"]: 
            raise BugFoundError(self.state, message="HeartBleed found!")

        a = super().run(fd, dst, length, flags)
        return a

class ngx_time_init_hook(angr.sim_procedure.SimProcedure):
    # Just stub it out, because we spend hours here
    def run(self):
        return

class dtls1_write_bytes_hook(angr.sim_procedure.SimProcedure):
    def run(self, ssl_st, msg_type, buffer, length):
        print(length)
