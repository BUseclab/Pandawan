#!/usr/bin/env python3

import os
import sys
import traceback
import pandare.plog_reader as pr

currentdir = os.path.dirname(os.path.realpath(__file__))
parentdir = os.path.dirname(currentdir)
sys.path.append(parentdir)
import paths as pt

sys.path.append(pt.firmsolo_dir)
import custom_utils as cu
import pickle

all_modules_accesses = {}
all_syscalls_seen = set()
images_accessing_mods = set()
modules_accessed = {}
procs_seen = {}
procs_to_mods = {}
procs_syscalls = {}
syscalls_freqs = {}
syscalls_to_modules = {}
syscall_to_kmod_info = {}

acceptable_syscalls = ["sys_setsockopt", "sys_getsockopt", "sys_connect", "sys_sendto", "sys_ioctl", "sys_write", "sys_socket", "sys_open", "sys_close", "sys_send", "sys_fcntl", "sys_read"]

fd_creator = {
    "sys_setsockopt" : "sys_socket",
    "sys_getsockopt" : "sys_socket",
    "sys_connect" : "sys_socket",
    "sys_send" : "sys_socket",
    "sys_sendto" : "sys_socket",
    "sys_write" : "sys_open",
    "sys_read" : "sys_open",
    "sys_ioctl" : "sys_open",
    "sys_fcntl" : "sys_open",
    "sys_close" : "sys_open",
}

class FuzzedImage():
    def __init__(self, image, arch, endian, pool):
        self.image = image
        self.arch = arch
        self.endian = endian
        self.pool = pool
  
    def find_module_name(self, address):
        address = address.replace("0x","")
        if "mips" in self.arch:
            kernel_addr = int(0x80000000)
        elif "arm" in self.arch:
            kernel_addr = int(0xc0000000)

        min_diff = 5000000000
        where = ""
        mod_addr = int(address, 16)

        diff_a1 = mod_addr - kernel_addr
        if diff_a1 > 0:
            if diff_a1 < min_diff:
                min_diff = diff_a1
                where = "kernel"
        for data in self.module_data:
            mod = data[0]
            addr = int(data[1], 16)
            size = data[2]

            diff_a1 = mod_addr - addr

            if diff_a1 > 0:
                if diff_a1 < min_diff:
                    min_diff = diff_a1
                    where = mod
        return where
    
    def parse_serial_log(self):
        self.module_data = []
        module_name = None
        
        serial_log = f"{pt.output_dir}/pandawan_results/scratch/{self.image}/qemu.final.serial.log"
        try:
            serial_out = cu.read_file(serial_log)
        except:
            print("Serial out for", self.image, "does not exist")
            serial_out = []

        for line in serial_out:
            if "Module_name:" in line:
                tk = line.split("Module_name:")[1]
                tokens = tk.split()
                module_name = tokens[0]
                if module_name == "kernel":
                    continue
                self.module_data.append([module_name, tokens[2], tokens[4]])
    
    def get_module_name(self, address):
        try:
            module_name = self.find_module_name(address)
        except:
            raise
        
        return module_name

    def __get_context(self):
        trace_fl = f"{pt.output_dir}/pandawan_results/scratch/{self.image}/exec_context.pkl"
        try:
            exec_traces = cu.read_pickle(trace_fl)
        except:
            exec_traces = {}
            raise
        
        self.exec_traces = exec_traces
    
    def __get_exec_trace(self):
        trace_fl = f"{pt.output_dir}/pandawan_results/scratch/{self.image}/exec_trace.pkl"
        try:
            procs_to_kmods = cu.read_pickle(trace_fl)
        except:
            procs_to_kmods = {}
            raise
        
        self.procs_to_kmods = procs_to_kmods
    
    def __get_called_syms(self):
        syscalls_to_mods = {}
        ### Get the execution trace information
        ### These are the addresses of the symbols called
        self.parse_serial_log()
        self.__get_context()
        seen_mods = set()

        if "mips" in self.arch:
            mod_lower_bound = "c0000000"
            mod_upper_bound = "c2000000"
        elif "arm" in self.arch:
            mod_lower_bound = "bf000000"
            mod_upper_bound = "c0000000"
        
        for exec_trace in self.exec_traces:
            print("Checking exec_trace", exec_trace)
            if "sys_init_module" in exec_trace:
                continue
            tokens = exec_trace.split("_")
            try:
                indx = tokens.index("sys")
            except:
                continue
            system_call = "_".join(tokens[indx:])
            proc_name = "_".join(tokens[0:indx-4])
            pid = tokens[indx-4]
            asid = tokens[indx-3]
            create_time = tokens[indx-2]
            syscall_id = tokens[indx-1]
            proc_id = f"{pid}_{asid}_{create_time}"
            for address in self.exec_traces[exec_trace]:
                if int(address.replace("0x", ""), 16) >= int(mod_lower_bound, 16) and int(address.replace("0x",""), 16) <= int(mod_upper_bound, 16):
                    module_name = self.get_module_name(address)
                    if module_name and module_name != "kernel":
                        if proc_id not in procs_seen:
                            procs_seen[proc_id] = proc_name
                        if exec_trace not in syscalls_to_mods:
                            syscalls_to_mods[exec_trace] = set()
                        syscalls_to_mods[exec_trace].add(module_name)
                        if module_name not in modules_accessed and module_name not in seen_mods:
                            modules_accessed[module_name] = 1
                        elif module_name in modules_accessed and module_name not in seen_mods:
                            modules_accessed[module_name] +=1
                        seen_mods.add(module_name)
        
        return syscalls_to_mods
    
    def __get_procs_to_kmods(self):
        ### Get the execution trace information
        ### These are the addresses of the symbols called
        self.__get_exec_trace()

        if "mips" in self.arch:
            mod_lower_bound = "c0000000"
            mod_upper_bound = "c2000000"
        elif "arm" in self.arch:
            mod_lower_bound = "bf000000"
            mod_upper_bound = "c0000000"
        
        for proc in self.procs_to_kmods:
            tokens = proc.split("_")
            pid = tokens[-3]
            asid = tokens[-2]
            create_time = tokens[-1]
            proc_id = f"{pid}_{create_time}"
            for address in self.procs_to_kmods[proc]:
                if int(address.replace("0x", ""), 16) >= int(mod_lower_bound, 16) and int(address.replace("0x",""), 16) <= int(mod_upper_bound, 16):
                    module_name = self.get_module_name(address)
                    if module_name and module_name != "kernel":
                        if proc_id not in procs_to_mods:
                            procs_to_mods[proc_id] = set()
                        procs_to_mods[proc_id].add(module_name)
    
    def filter_syscalls(self, syscalls_to_mods):
        for trace in syscalls_to_mods:
            tokens = trace.split("_")
            try:
                indx = tokens.index("sys")
            except:
                print("Invalid trace", trace)
                continue
            system_call = "_".join(tokens[indx:])
            proc_name = "_".join(tokens[0:indx-4])
            pid = tokens[indx-4]
            create_time = tokens[indx-2]
            target_syscall_id = tokens[indx-1]
            proc_id = f"{pid}_{create_time}"
            if system_call == "sys_open" or  system_call == "sys_socket":
                continue
            if proc_id not in procs_syscalls:
                continue
            open_and_socket = []
            for msg in procs_syscalls[proc_id]:
                syscall_name = msg.syscall.call_name
                proc_pid = msg.syscall.pid
                proc_create_time = msg.syscall.create_time
                proc_asid = msg.asid
                syscall_id = msg.syscall.syscall_id
                
                if syscall_name == "sys_socket" or syscall_name == "sys_open":
                    the_syscall = [syscall_name, proc_pid, proc_asid, proc_create_time, syscall_id]
                    syscall_arg_vals = []
                    for arg in msg.syscall.args:
                        syscall_arg_vals.append(str(arg))
                    retcode = msg.syscall.retcode
                    the_syscall.append(syscall_arg_vals)
                    the_syscall.append(retcode)
                    open_and_socket.append(the_syscall)
                    continue

                if syscall_name in acceptable_syscalls and int(syscall_id) == int(target_syscall_id):
                    the_syscall = [syscall_name, proc_pid, proc_asid, proc_create_time, syscall_id]
                    syscall_arg_vals = []
                    for arg in msg.syscall.args:
                        if arg.arg_name == "buf" or arg.arg_name == "optval":
                            syscall_arg_vals.append(bytes(arg.bytes_val))
                        else:
                            syscall_arg_vals.append(str(arg))
                    the_syscall.append(syscall_arg_vals)
                    target_fd_creator = None
                    if syscall_name in fd_creator:
                        target_fd_creator = fd_creator[syscall_name]
                    else:
                        the_syscall = []
                        continue
                    for open_or_socket in open_and_socket[::-1]:
                        fd_creator_syscall = open_or_socket[0]
                        if target_fd_creator and target_fd_creator != fd_creator_syscall:
                            continue
                        ### Check the file descriptor of the syscall if it matches
                        ### the fd returned by open or socket
                        fd = syscall_arg_vals[0].split("\n")[1].split(": ")[1].strip('"')
                        if int(fd) == int(open_or_socket[-1]):
                            images_accessing_mods.add(self.image)
                            if proc_id not in syscall_to_kmod_info:
                                syscall_to_kmod_info[proc_id] = []
                            syscall_to_kmod_info[proc_id].append(open_or_socket)
                            syscall_to_kmod_info[proc_id].append(the_syscall)
                            break
        
    def process_panda_logs(self, syscalls_to_mods):
        for msg in self.log_data:
            proc_asid = msg.asid
            if msg.HasField("syscall"):
                proc_pid = msg.syscall.pid
                proc_create_time = msg.syscall.create_time
                syscall_id = msg.syscall.syscall_id
                proc_id = f"{proc_pid}_{proc_create_time}"
                ### Asign the systemcalls to the procs
                if proc_id in procs_to_mods:
                    if proc_id not in procs_syscalls:
                        procs_syscalls[proc_id] = []
                    procs_syscalls[proc_id].append(msg)

        self.filter_syscalls(syscalls_to_mods)
    
    def find_syscalls(self, syscalls_to_mods):
        global all_syscalls_seen
        for trace in syscalls_to_mods:
            tokens = trace.split("_")
            try:
                index = tokens.index("sys")
            except:
                return
            syscall = "_".join(tokens[index:])
            if "sys" in syscall:
                if syscall not in syscalls_freqs:
                    syscalls_freqs[syscall] = 1
                else:
                    syscalls_freqs[syscall] += 1
                    
                if syscall not in all_syscalls_seen:
                    all_syscalls_seen.add(syscall)
    
    def get_panda_logs(self):
        panda_log = f"{pt.output_dir}/pandawan_results/scratch/{self.image}/results.plog"
        try:
            log_data = pr.PLogReader(panda_log)
        except:
            log_data = None
        
        self.log_data = log_data
    
    def get_module_traces(self):
        syms = self.__get_called_syms()
        self.__get_procs_to_kmods()
        self.get_panda_logs()
        self.process_panda_logs(syms)
        
        return syms

def run_analysis(image):
    global all_syscalls_seen
    global syscalls_to_modules
    which_info = ["arch", "endian", "kernel", "modules"]
    try:
        info = cu.read_pickle(f"{pt.output_dir}/pandawan_results/Image_Info/{image}.pkl")
    except:
        print("No image info for", image)
        return
    
    pool = None
    arch, endian, kernel, modules = info['arch'], info['endian'], info['kernel'], info['modules']
    
    image_obj = FuzzedImage(image, arch, endian, pool)
    try:
        traces = image_obj.get_module_traces()
    except:
        print(traceback.format_exc())
        traces = {}

    if syscall_to_kmod_info != {}:
        print("Image", image, "Number of seeds", len(syscall_to_kmod_info))
        with open(f"{pt.output_dir}/pandawan_results/scratch/{image}/syscall_traces.pkl", "wb") as f:
            pickle.dump(syscall_to_kmod_info, f, 2)
    else:
        print("Image", image, "no seeds created")

def main():
    global all_syscalls_seen
    global syscalls_to_modules
    image = sys.argv[1]
    run_analysis (image)   

if __name__ == "__main__":
    main()
