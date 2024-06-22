import json
import traceback
from pandare import PyPlugin
import os
import sys
import subprocess as sb
import pickle

syscall_tag = None

syscall_arg_types = {
    "0": "syscall_arg_u64",
    "1" : "syscall_arg_u32",
    "2" : "syscall_arg_u16",
    "16" : "syscall_arg_s64",
    "17" : "syscall_arg_s32",
    "18" : "syscall_arg_s16",
    "32" : "syscall_arg_buf_ptr",
    "33" : "syscall_arg_struct_ptr",
    "34" : "syscall_arg_str_ptr",
    "48" : "syscall_arg_struct",
    "49" : "syscall_arg_arr",
}


class KmodFuncTracer(PyPlugin):
    def __init__(self, panda):
        self.panda = panda
        self.panda.exec_traces = {}
        self.panda.exec_context = {}
        self.panda.procs_seen = {}
        self.scratch = self.get_arg("scratch")
        self.current_tag = str()
        self.processes = {}
        self.current_syscall = 0
        self.hook_module_ranges()
        print("Setting up KmodFuncTracer")
        
        @panda.ppp("syscalls2", "on_all_sys_enter2")
        def before_syscall_execute(cpu, pc, call, rp):
            global syscall_tag
            self.current_syscall += 1
            if not call or not rp:
                return
            current_process = panda.plugins['osi'].get_current_process(cpu)
            asid = current_process.asid
            try:
                process_name = panda.ffi.string(current_process.name).decode('utf8', 'ignore')
            except:
                print("Kernel function traces NULL process")
                process_name = "error"
            create_time = current_process.create_time
            pid = current_process.pid
            sysc_id = rp.syscall_id
            syscall_id = self.current_syscall
            
            syscall_name =panda.ffi.string(call.name).decode("utf-7", "ignore")
            tag = f"{process_name}_{pid}_{asid}_{create_time}"
            
            if tag not in self.panda.procs_seen:
                self.panda.procs_seen[tag] = []
            self.panda.procs_seen[tag].append([syscall_name, syscall_id])

        @panda.ppp("syscalls2", "on_all_sys_return")
        def after_syscall_execute(cpu, pc, callno):
            global syscall_tag
            pass
            

    def hook_module_ranges(self):
        def make_hook(addr):
            if "mips" in self.panda.arch_name:
                mod_lower_bound = "c0000000"
                mod_upper_bound = "c2000000"
            elif "arm" in self.panda.arch_name:
                mod_lower_bound = "bf000000"
                mod_upper_bound = "c0000000"
            
            @self.panda.syscall_to_mod_trace(addr, kernel=True, cb_type="before_block_exec", low_bound=int(mod_lower_bound, 16), upper_bound=int(mod_upper_bound, 16))
            def call_hook(cpu, tb, h):
                global syscall_tag
                ### Get the current process from the context
                current_process = self.panda.plugins['osi'].get_current_process(cpu)
                asid = current_process.asid
                process_name = self.panda.ffi.string(current_process.name).decode('utf8', 'ignore')
                create_time = current_process.create_time
                pid = current_process.pid
                tag = f"{process_name}_{pid}_{asid}_{create_time}"
                
                ### Get the PC value. This will tell us if we are in module code
                pc = self.panda.arch.get_pc(cpu)
                    
                if int(pc) >= int(mod_lower_bound, 16) and int(pc) <= int(mod_upper_bound, 16):
                    if tag not in self.panda.procs_seen:
                        if tag not in self.panda.exec_context:
                            self.panda.exec_context[tag] = set()
                        self.panda.exec_context[tag].add(hex(pc))
                    else:
                        last_syscall = self.panda.procs_seen[tag][-1]
                        new_tag = f"{tag}_{last_syscall[1]}_{last_syscall[0]}"
                        if new_tag not in self.panda.exec_context:
                            self.panda.exec_context[new_tag] = set()
                        self.panda.exec_context[new_tag].add(hex(pc))
                    if tag not in self.panda.exec_traces:
                        self.panda.exec_traces[tag] = set()
                    self.panda.exec_traces[tag].add(hex(pc))
            
        make_hook(0)

    def uninit(self):
        try:
            with open(f"{self.scratch}/pandawan_results/exec_trace.pkl", "wb") as f:
                pickle.dump(self.panda.exec_traces, f)
            with open(f"{self.scratch}/pandawan_results/exec_context.pkl", "wb") as f:
                pickle.dump(self.panda.exec_context, f)
        except:
            pass
        pass
