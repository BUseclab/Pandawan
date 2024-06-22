import json
from pandare import PyPlugin
import pickle
import threading
import os
import sys
import time
import Levenshtein as lv
import subprocess as sb

#sys.path.append("/exp_scripts/collection_plugins/")
python_time = None
mutex = threading.Lock()

class FwInitStopFinder(PyPlugin):
    def __init__(self, panda):
        fw_name = self.get_arg("fw_name")
        logfile = self.get_arg("logfile")
        global_logs = self.get_arg("global_logs")
        panda_pid = self.get_arg("panda_pid")
        try:
            self.time_frame = int(self.get_arg("time_frame"))
            if self.time_frame < 5:
                self.time_frame = 80
        except Exception as e:
            print(e)
            
        self.fw_id = 0
        self.result = 0
        self.prev_proc = None
        self.prev_time = 0
        self.init_time = time.time()
        self.last_proc_time = 0
        self.seen_procs = set()
        self.last_proc = "n/a"
        self.unique_proc_times = {}
        self.logfile = logfile
        self.proc_info = {}

        # if set, don't write output, just end anlaysis
        self.skip_log = self.get_arg_bool("skip_log")

        if fw_name:
            self.fw_id = (fw_name.split("/")[-1]).split(".")[0]

        self.outfile = f"{global_logs}"

        if not os.path.exists(self.outfile):
            with open(self.outfile, "w") as f:
                f.write("fwid, saw_last_unique_proc, which_proc, proc_create_time\n")
        
        self.panda = panda
        self.time_thread = Thread(panda, self.time_frame, self.init_time, panda_pid)
        self.time_thread.daemon = True
        self.time_thread.start()

        @self.panda.ppp("syscalls2", "on_sys_exit_enter")
        def on_exit(cpu, pc, retval):
            try:
                proc_pid, proc_create_time, proc_name = self.get_current_proc(cpu)
                if not proc_pid:
                    return
                tag = f"{proc_pid}_{proc_create_time}"
                if tag not in self.proc_info:
                    self.proc_info[tag] = {}
                    self.proc_info[tag]['name'] = proc_name
                    if retval:
                        self.proc_info[tag]['retcode'] = retval
                    else:
                        self.proc_info[tag]['retcode'] = None
                else:
                    if 'name' not in self.proc_info['tag']:
                        self.proc_info[tag]['name'] = proc_name
                    if retval:
                        self.proc_info[tag]['retcode'] = retval
                    else:
                        self.proc_info[tag]['retcode'] = None
            except:
                pass

        @self.panda.ppp("syscalls2", "on_sys_exit_group_enter")
        def on_exit_group(cpu, pc, retval):
            try:
                proc_pid, proc_create_time, proc_name = self.get_current_proc(cpu)
                if not proc_pid:
                    return
                tag = f"{proc_pid}_{proc_create_time}"
                if tag not in self.proc_info:
                    self.proc_info[tag] = {}
                    self.proc_info[tag]['name'] = proc_name
                    if retval:
                        self.proc_info[tag]['retval'] = retval
                    else:
                        self.proc_info[tag]['retval'] = None
                else:
                    if 'name' not in self.proc_info['tag']:
                        self.proc_info[tag]['name'] = proc_name
                    if retval:
                        self.proc_info[tag]['retcode'] = retval
                    else:
                        self.proc_info[tag]['retcode'] = None
            except:
                pass
        
        @panda.ppp("syscalls2", "on_sys_execve_enter")
        def on_execve(cpu, pc, pathname, argv, envp):
            global python_time
            global mutex
            try:
                mutex.acquire()
                newproc = self.get_execve_string(cpu, pathname, argv)
                prev_time = python_time
                python_time = time.time()
                proc_pid, proc_create_time, proc_name = self.get_current_proc(cpu)
                unique_proc = "Not Unique"
                tag = f"{proc_pid}_{proc_create_time}"
                if tag not in self.proc_info:
                    self.proc_info[tag] = {}
                    self.proc_info[tag]['name'] = proc_name
                

                for proc in self.seen_procs:
                    lev_ratio = lv.ratio(proc, newproc)
                    if lev_ratio >=0.5:
                        self.unique_proc_times[newproc] = [proc_pid, proc_create_time, round(python_time - self.init_time, 2), unique_proc]
                        python_time = prev_time
                        mutex.release()
                        return

                self.last_proc_time = python_time
                mutex.release()
                self.seen_procs.add(newproc)
                self.last_proc = newproc
                unique_proc = "Unique"
                #self.unique_proc_times[newproc] = round(self.last_proc_time - self.init_time, 2)
                self.unique_proc_times[newproc] = [proc_pid, proc_create_time, round(python_time - self.init_time, 2), unique_proc]

            except ValueError:
                if self.result == 0:
                    self.result = "error"
                return
        
        @panda.ppp("syscalls2", "on_sys_execveat_enter")
        def on_execveat(cpu, pc, pathname, argv, envp):
            global python_time
            global mutext
            try:
                mutex.acquire()
                newproc = self.get_execve_string(cpu, pathname, argv)
                prev_time = python_time
                python_time = time.time()
                #self.unique_proc_times[newproc] = round(python_time - self.init_time, 2)
                proc_pid, proc_create_time, proc_name = self.get_current_proc(cpu)
                unique_proc = "Not Unique"

                tag = f"{proc_pid}_{proc_create_time}"
                if tag not in self.proc_info:
                    self.proc_info[tag] = {}
                    self.proc_info[tag]['name'] = proc_name
                
                for proc in self.seen_procs:
                    lev_ratio = lv.ratio(proc, newproc)
                    if lev_ratio >= 0.5:
                        self.unique_proc_times[newproc] = [proc_pid, proc_create_time, round(python_time - self.init_time, 2), unique_proc]
                        python_time = prev_time
                        mutex.release()
                        return

                self.last_proc_time = python_time
                mutex.release()
                self.seen_procs.add(newproc)
                self.last_proc = newproc
                self.last_proc = newproc
                unique_proc = "Unique"
                #self.unique_proc_times[newproc] = round(self.last_proc_time - self.init_time, 2)
                self.unique_proc_times[newproc] = [proc_pid, proc_create_time, round(python_time - self.init_time, 2), unique_proc]

            except ValueError:
                if self.result == 0:
                    self.result = "error"
                return

    def get_current_proc(self, cpu):
        proc = self.panda.plugins['osi'].get_current_process(cpu)
        if proc == self.panda.ffi.NULL:
            print("Error determining current process")
            return None, None, None
        if proc.name ==  self.panda.ffi.NULL:
            return proc.pid, proc.create_time, "N/A"
        procname = self.panda.ffi.string(proc.name).decode('utf8', 'ignore')
            
        return proc.pid, proc.create_time, procname

    def get_proc(self, cpu):
        proc = self.panda.plugins['osi'].get_current_process(cpu)
        if proc == self.panda.ffi.NULL:
            print("Error determining current process")
            return []
        create_time = proc.create_time

        return int(create_time / 1000000000)

    def get_execve_string(self, cpu, fname_ptr, argv_ptr):
        fname = "error"
        try: fname = self.panda.read_str(cpu, fname_ptr)
        except ValueError: pass
        argv = []

        try: argv_buf = self.panda.virtual_memory_read(cpu, argv_ptr, 64, fmt='ptrlist')
        except ValueError as e:
            argv_buf = []
            argv = ["error"]

        for ptr in argv_buf:
            if ptr == 0:
                break
            arg = "[error]"
            try: arg = self.panda.read_str(cpu, ptr)
            except ValueError: pass
            argv.append(arg)

        return fname + (' ' if len(argv) else '') + ' '.join(argv[1:] if len(argv) else [])

    def uninit(self):
        try:
            self.time_thread.kill()
        except:
            pass
        try:
            self.time_thread.join(timeout = 10)
        except:
            pass
        if not self.skip_log:
            elapsed_time = (time.time() - self.init_time)
            with open(self.outfile, "a") as f:
                if self.seen_procs:
                    f.write(f"{self.fw_id}, {self.result}, {self.last_proc}, {round(elapsed_time, 2)}, {round(self.last_proc_time - self.init_time, 2)}\n")
                else:
                    f.write(f"{self.fw_id}, {self.result}, n/a, n/a\n")
            with open(self.logfile, "w") as f:
                for proc in self.unique_proc_times:
                    f.write(f"{self.unique_proc_times[proc][-1]} Proc: {proc} PID: {self.unique_proc_times[proc][0]} Creation Time: {self.unique_proc_times[proc][1]} invoked at time {self.unique_proc_times[proc][2]}\n")
            
            tokens = self.logfile.split("/")
            result_dir = "/".join(tokens[:-1])
            proc_ret_code_info_file = f"{result_dir}/proc_ret_codes.pkl"
            with open(proc_ret_code_info_file, "wb") as f:
                pickle.dump(self.proc_info, f)

class Thread(threading.Thread):
    def __init__(self, panda, time_frame, init_time, panda_pid):
        threading.Thread.__init__(self)
        self.panda = panda
        self.time_frame = time_frame
        self.init_time = init_time
        self.panda_pid = panda_pid

    def stop_pandawan(self):
        res = ""
        try: 
            pid_to_kill = "ps aux | grep run.py"
            res = sb.check_output(pid_to_kill, shell=True).decode("utf-8")
            print(res)
        except Exception as e:
            pass
        
        #if res != "": 
            #results = res.split("\n")
            #for rs in results:
                #if "grep" not in rs: 
                    #if rs.split() == []: 
                        #continue
                    #pid = int(rs.split()[1])
        print("Killing Panda pid",self.panda_pid)
        try:
            sb.run(["kill", "-15", f"{self.panda_pid}"])
            time.sleep(2)
            sb.run(["kill", "-9", f"{self.panda_pid}"])
        except Exception as e:
            print(e)

        time.sleep(2)

    def run(self):
        global python_time
        global mutex
        while True:
            time.sleep(5)
            if not python_time:
                current_time = time.time()
                total_time = current_time - self.init_time
           #     print("Total time", total_time)
                if int(total_time) >= 80:
            #        print("Stopping Pandawan")
                    self.stop_pandawan()
                else:
                    continue
            else:
                mutex.acquire()
                current_time = time.time()
                elapsed_time = current_time - python_time
                mutex.release()
         #       print("Elapsed time", elapsed_time, "Python time", python_time)
                if int(elapsed_time) > self.time_frame:
          #          print("LABELS: Time elapsed above 80 sec returning")
                    break
        self.panda.result = 1
        self.panda.end_analysis()
