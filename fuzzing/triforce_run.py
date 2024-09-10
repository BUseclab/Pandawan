#!/usr/bin/env python3



import os
import sys
currentdir = os.path.dirname(os.path.realpath(__file__))
parentdir = os.path.dirname(currentdir)
sys.path.append(parentdir)
import paths as pt
sys.path.append(pt.firmsolo_dir)
import subprocess as sb
from multiprocessing import Pool
from dataclasses import dataclass
import argparse as argp
import traceback
import custom_utils as cu
import csv
import threading
import time

delimeter = "\xa5\xc9"
calldelim = "\xb7\xe3"

init_template = """#!/bin/sh                                                                                                                              
mount -t proc proc /proc                                                                                                               
#mount -t sysfs none /sys                                                                                                              
mount -t debugfs none /sys/kernel/debug                                                                                                
mount -t devtmpfs none /dev                                                                                                            
#mount -t tmpfs none /tmp                                                                                                              
#chmod 777 / /tmp                                                                                                                      
mkdir -p /dev/pts                                                                                                                      
mkdir -p /dev/shm                                                                                                                      
mount -a                                                                                                                               
hostname -F /etc/hostname                                                                                                              
                                                                                                                                       
/etc/init.d/rcS                                                                                                                        

# note: it may be useful to run a "heater" program here                                                                                
# that warms up the QEMU JIT cacheore starting the                                                                                     
# AFL fork server:                                                                                                                     
#                                                                                                                                      
# /bin/heater /heaterfiles/*                                                                                                           
cd /root/
%(MODULES)s
%(MKNOD)s

#/bin/sh
exec /home/driver -v

"""
device_toggle = {"acos_nat_cli": 1, "brcmboard": 2, "dsl_cpe_api": 4, "gpio": 8, "nvram": 16, 
                 "pib": 32, "sc_led": 64, "tca0": 128, "ticfg": 256, "watchdog": 512, "wdt" : 1024,
                 "zybtnio": 2048}
enable_device = 4095

entry_dict = {}

class Thread(threading.Thread):
    def __init__(self, timeout, image):
        threading.Thread.__init__(self)
        self.timeout = timeout
        self.image = image
    def run(self):
        while True:
            time.sleep(self.timeout)
            cmd = f"echo /fuzzing/driver | nc -U /tmp/qemu.{self.image}.S1"
            try:
                res = sb.check_output(cmd, shell=True, timeout=10).decode("utf-8")
                print("SOCAT:", res)
            except:
                print(f"The socket connection for image {image} timed out. If the fuzzer is not running then there is an issue with the image's serial console.")
            break

class TriforceAFL:
    def __init__(self, image, cnt, out_fuzz_dir, timeout, f_init_time):
        self.image = image
        self.cnt = str(cnt)
        self.out_fuzz_dir = out_fuzz_dir
        self.target_dir = out_fuzz_dir
        self.timeout = timeout
        self.test_case = "0"   ### Case with char device
        self.have_mknod = True
        self.f_init_time = f_init_time
        ### Setup functions
        self.__get_image_info()

    def __get_image_info(self):
        self.kernel, self.arch, self.endian, self.modules, \
                     self.vermagic = get_module_info(self.image)

        if self.arch == "mips":
            self.start_addr = "c0000000"
            self.end_addr = "c2000000"
        elif self.arch == "arm":
            self.start_addr = "bf000000"
            self.end_addr = "c0000000"
        else:
            self.start_addr = "0"
            self.end_addr = "0"

    def __get_module_data(self):
        ### First get the panic and die address for the Kfs kernel
        self.panic, self.die = get_panic_die(self.image, self.kernel)

        ### Get the options for QEMU
        cu.loaded_mods_path = f"{pt.output_dir}/pandawan_results/Loaded_Modules/"
        mod_load_info_fl = f"{cu.loaded_mods_path}{self.image}/{self.image}_ups_subs.pkl"
        try:
            mod_load_info = cu.read_pickle(mod_load_info_fl)
            self.qemu_opts = mod_load_info[-1]
            self.loaded_modules = mod_load_info[0]
        except:
            print("Image {} does not have any load information yet...Run"
                  "stage 3 first".format(self.image))
            return False

        return True


    def __get_module_deps(self):

        success = self.__get_module_data()
        return success

    def __setup_qemu(self):
        global enable_device
        self.fuzz_cmd = None
        if self.arch == "mips":
            if self.endian == "little endian":
                qemu = "qemu-system-mipsel"
            else:
                qemu = "qemu-system-mips"
            self.kernel_path = \
                    f"{pt.output_dir}/pandawan_results/results/{self.image}/{self.kernel}/vmlinux"
        elif self.arch == "arm":
            qemu = "qemu-system-arm"
            self.kernel_path = \
                    f"{pt.output_dir}/pandawan_results/results/{self.image}/{self.kernel}/zImage"
        else:
            return False

        machine = self.qemu_opts["machine"]
        if self.qemu_opts["cpu"] != "":
            cpu = self.qemu_opts["cpu"]
        else:
            cpu = ""
        
        iface = self.qemu_opts["iface"]
        if iface != "":
            if self.qemu_opts['id'] != "" and self.qemu_opts['id'] != None:
                drive = "{},{}format=raw,{}".format(self.fs_path, self.qemu_opts['iface'], self.qemu_opts['id'])
            else:
                drive = "{},format=raw,{}".format(self.fs_path, iface)
        else:
            drive = "{},format=raw,{}".format(self.fs_path, iface)

        try:
            if self.qemu_opts['device'] != "" and self.qemu_opts['device'] != None:
                drive += f" {self.qemu_opts['device']}"
        except:
            pass
           
        blk_dev = self.qemu_opts["blk_dev"]
        if blk_dev == "/dev/hda":
            blk_dev = "/dev/hda1"
        elif blk_dev == "/dev/sda":
            blk_dev = "/dev/sda1"
        elif blk_dev == "/dev/vda":
            blk_dev = "/dev/vda1"
        else:
            blk_dev = "/dev/mmcblk0p1"

        tty = self.qemu_opts["tty"]
        
        net_opts = "-net nic -net socket,listen=:2001 -net nic -net socket,listen=:2002 -net nic -net socket,listen=:2003"
        
        FIRMAE_KERNEL = "true"
        for module in self.loaded_modules:
            if "acos_nat" in module:
                enable_device &= 4094
                FIRMAE_KERNEL="false"
            if "gpio" in module:
                enable_device &= 4087
        append_args = f"\"debug ignore_loglevel print-fatal-signals=1 user_debug=31 enable_device={enable_device} FIRMAE_NET=true FIRMAE_NVRAM=true FIRMAE_KERNEL={FIRMAE_KERNEL}\""
        
        fuzzer_args = \
                f"-t 900 -m 6144 -i {self.input_dir} -o {self.input_dir_min} -QQ -- {qemu} -L {cu.tafl_dir}/qemu_mode/qemu/pc-bios -kernel {self.kernel_path} -drive file={drive} -m 256M -serial stdio -append \"root={blk_dev} rw rootwait console={tty} nandsim.parts=64,64,64,64,64,64,64,64,64,64 debug ignore_loglevel print-fatal-signals=1 user_debug=31 enable_device={enable_device} FIRMAE_NET=true FIRMAE_NVRAM=true FIRMAE_KERNEL={FIRMAE_KERNEL} fdyne_reboot=1 fdyne_execute=1 firmadyne.procfs=1 firmadyne.devfs=1 mem=256M\" -M {machine} {cpu} -serial unix:/tmp/qemu.{self.image}.S1,server,nowait -serial unix:/tmp/qemu.{self.image}.S2,server,nowait {net_opts} -display none -aflPanicAddr {self.panic} -aflDmesgAddr {self.die} -snapshot -aflFile @@"

        self.minimizer = f"timeout --foreground 950 {cu.tafl_dir}/afl-cmin {fuzzer_args}"
        print("Minimizing cmd", self.minimizer)
        
        if self.input_dir != "-":
            self.run_minimizer()
        
        if not os.listdir(self.input_dir_min):
            self.input_dir_min = self.input_dir
        
        self.fuzz_cmd = f"timeout -k 10 {self.timeout} {cu.tafl_dir}/afl-fuzz -M {self.banner} -t 900+ -m 6144 -i {self.input_dir_min} -o {self.target_dir} -QQ -- {qemu} -L {cu.tafl_dir}/qemu_mode/qemu/pc-bios -kernel {self.kernel_path} -drive file={drive} -m 256M -serial stdio -append \"root={blk_dev} rw rootwait console={tty} nandsim.parts=64,64,64,64,64,64,64,64,64,64 debug ignore_loglevel print-fatal-signals=1 user_debug=31 enable_device={enable_device} FIRMAE_NET=true FIRMAE_NVRAM=true FIRMAE_KERNEL={FIRMAE_KERNEL} fdyne_reboot=1 fdyne_execute=1 firmadyne.procfs=1 firmadyne.devfs=1 mem=256M\" -M {machine} {cpu} -serial unix:/tmp/qemu.{self.image}.S1,server,nowait -serial unix:/tmp/qemu.{self.image}.S2,server,nowait {net_opts} -display none -aflPanicAddr {self.panic} -aflDmesgAddr {self.die} -snapshot -aflFile @@"
        
        print("Fuzzer cmd is", self.fuzz_cmd)
        return True

    def run_minimizer(self):
        print("Spawning Timer Thread for minimizer. Will wait for", self.f_init_time, "seconds")
        self.time_thread = Thread(self.f_init_time, self.image)
        self.time_thread.daemon = True
        self.time_thread.start()

        try:
            retcode = os.system(self.minimizer)
            if int(retcode) == 124 and os.listdir(self.input_dir_min) == []:
                print("Minimizing had no effect going back to default input dir")
                self.input_dir_min = self.input_dir
        except:
            print("Unsuccessful minimizing for", self.image, self.banner)
            print(traceback.format_exc())
            self.input_dir_min = self.input_dir
        
        try:
            self.time_thread.kill()
        except:
            pass
        try:
            self.time_thread.join(timeout = 5)
        except:
            pass

    def fix_fs(self):
        
        self.fs_path = f"{pt.output_dir}/pandawan_results/scratch/{self.image}/image.raw"
        print("Filesystem", self.fs_path)

    def copy_fuzz_data(self):
        the_start_addr = str(int(self.start_addr, 16))
        the_end_addr = str(int(self.end_addr, 16))
        cp_cmd = ["python2", f"{cu.script_dir}/fuzzing_scripts/copy_fuzz_data.py",
                the_start_addr, the_end_addr, self.dev_name_path,
                self.copy_data_file, self.test_case]
        try:
            sb.run(cp_cmd)
        except:
            print(traceback.format_exc())
            return False

        return True

    def get_module_data(self):
        success = self.__get_module_deps()
        return success

    def setup_afl(self):
        self.banner = f"{self.image}_pandawan"

        ### Get the module data: Dependencies, Substitutions, etc
        success = self.get_module_data()
        if not success:
            print("Could not get module info for image", self.image)
            return success

        ### The filesystem to be used
        self.fix_fs()
        ### AFL arguments
        self.fuzzer_path = f"/TriforceAFL/"
        self.input_dir_min = f"{self.out_fuzz_dir}/inputs_min/"
        
        self.input_dir = fix_inputs(self.image, self.arch, self.endian, self.out_fuzz_dir)
        
        ### Triforce QEMU setup
        success = self.__setup_qemu()
        if not success:
            print("Could setup QEMU for image", self.image)
            return success

        return True

    def run_the_fuzzer(self):
        success = self.setup_afl()
        if not success:
            print(f"Something went wrong when setting up TriforceAFL for image {self.image} and banner {self.banner}")
            return
        ### Main fuzzer run
        if not self.fuzz_cmd:
            print(f"Something went wrong when setting up TriforceAFL for image {self.image} and banner {self.banner}")
        
        print("Spawning Timer Thread for fuzzer. Will wait for", self.f_init_time, "seconds")

        self.time_thread = Thread(self.f_init_time, self.image)
        self.time_thread.daemon = True
        self.time_thread.start()
        
        curr_cwd = os.getcwd()
        try:
            fuzzer = sb.Popen(self.fuzz_cmd, cwd=curr_cwd, shell=True)
        except:
            print(traceback.format_exc())
        
        try:    
            fuzzer.wait(timeout = self.timeout)
        except:
            print(f"Image: {self.image} was successfully fuzzed")
            print("Timeout expired for process", str(fuzzer.pid))
        
        try:
            self.time_thread.kill()
        except:
            pass
        try:
            self.time_thread.join(timeout = 5)
        except:
            pass

#########################################################################

####################### Get panic and die addresses for the image ###############
def get_panic_die(image,kernel):
    cu.result_dir_path = f"{pt.output_dir}/pandawan_results/results/"
    system_map = "{}/{}/{}/System.map".format(cu.result_dir_path,image,kernel)
    
    symbols = cu.read_file(system_map)
    
    for line in symbols:
        tokens = line.split()
        if tokens[2] == "panic":
            panic = tokens[0].replace("ffffffff","")
        if tokens[2] == "die":
            die = tokens[0].replace("ffffffff","")
    return panic,die
#################################################################################

##################### Fix inputs for the fuzzer ########################
def fix_inputs(image, arch, endian, out_fuzz_dir):
    inpt_dir = f"{out_fuzz_dir}/inputs/"

    #if os.path.exists(inpt_dir):
        #return inpt_dir

    mkdir = ["mkdir", inpt_dir]
    ### Create the dir if it does not exist
    try:
        sb.run(mkdir)
    except:
        print(traceback.format_exc())
        pass
    if endian == "little endian":
        endian = "le"
    else:
        endian = "be"
    ### Create the inputs for the fuzzer
    create_inpt = "python2 {}/pandawan/gen_pandawan.py -f {} -a {} -e {} -i {} -r {}".format(cu.tafl_lsf_dir,image, arch, endian, inpt_dir, pt.output_dir)

    print("Running", create_inpt)
    try:
        sb.run(create_inpt, shell = True)
    except:
        print(traceback.format_exc())
        print("Could not create the input seeds for image",image)

    return inpt_dir

#########################################################################
def check_if_fs_exists(image,path):
    if os.path.exists(path):
        return True
    else:
        return False
########################################################################

def check_if_cont(out_dir, banner):
    try:
        fl = f"{out_dir}/{banner}/fuzzer_stats"
        lines = cu.read_file(fl)
    except:
        return None

    path_num = 0
    last_path_time = 0
    last_update_time = 0
    for line in lines:
        if "paths_total" in line:
            tokens = line.split()
            path_num = int(tokens[2])
        if "last_path" in line:
            tokens = line.split()
            last_path_time = int(tokens[2])
        if "last_update" in line:
            tokens = line.split()
            last_update_time = int(tokens[2])
    last_path_discovered = last_update_time - last_path_time

    if path_num > 1 and last_path_time >0  and last_path_discovered < 7200:
        return True
    else:
        return False

################### Data class for passing input to workers ################

@dataclass
class FuzzData:
    img_name: str
    out_fuzz_dir: str
    counter: int               #Needed for creating a temp file
    timeout: int
    f_init_time: int
###########################################################################

def create_output_dirs(out_fuzz_dir,subdir):
    try:
        os.mkdir(out_fuzz_dir + subdir)
    except:
        print("Directory",out_fuzz_dir + subdir,"already exists")
        #print(traceback.format_exc())


def create_directories(image):
    out_fuzz_dir = cu.abs_path + "Fuzz_Results_Cur/" + image + "/"

    try:
        os.mkdir(out_fuzz_dir)
    except:
        print("Directory",out_fuzz_dir,"already exists")

    return out_fuzz_dir

###################### Essential Info about the module ###########################

def get_module_info(image):
    
    cu.img_info_path = f"{pt.output_dir}/pandawan_results/Image_Info/"
    which_info = ["kernel","arch","endian","modules","vermagic"]
    
    info = cu.get_image_info(image, which_info)

    kernel = "linux-" + info[0]
    arch = info[1]
    endianess = info[2]
    modules = info[3]
    vermagic = info[4]

    return kernel,arch,endianess, modules,vermagic

##################################################################################

def save_bad_testcase(out_fuzz_dir,bad_cmd):
    outfile = out_fuzz_dir + "bad_testcases"
    with open(outfile,"a") as f:
        f.write(bad_cmd + "\n")

def cleanup(data_fname):
    try:
        res = sb.run(["rm","-rf",data_fname],shell=False)
    except Exception as e:
        print(e)
        print(traceback.format_exc())

#################### Function for every worker #######################
def start_fuzz(fuzz_data):
    image = fuzz_data.img_name
    cnt = fuzz_data.counter
    #print("Inside worker",cnt)
    out_fuzz_dir = fuzz_data.out_fuzz_dir
    
    timeout = fuzz_data.timeout
    f_init_time = fuzz_data.f_init_time

    triforce = TriforceAFL(image, cnt, out_fuzz_dir, timeout, f_init_time)
    try:
        triforce.run_the_fuzzer()
    except:
        print(traceback.format_exc())

######################################################################

#################### Generic Fuzzing #################################

def data_append(image,kernel,arch,endianess,image_num,out_fuzz_dir):

    data = []
    data.append(image)
    data.append(kernel)
    data.append(arch)
    data.append(endianess)
    data.append(image_num)
    data.append(out_fuzz_dir)

    return data
######################################################################

def get_ifin_stock(image):

    cnt = 0
    avg = 0
    for i in range(1,4):
        proc_log_file = f"{pt.output_dir}/pandawan_results/scratch/{image}/proc_logs.txt"
        try:
            with open(proc_log_file, "r") as f:
                tasks = f.readlines()
            cnt += 1
        except:
            continue
        for ln in tasks[::-1]:
            if "Not Unique Proc:" in ln: continue
            last_task_time = float(ln.split()[-1])
            avg += last_task_time
            break
   
    avg = int(avg / cnt)
    return avg

if __name__ == "__main__":

    parser = argp.ArgumentParser(description='Fuzz a firmware kernel module')
    parser.add_argument('-i','--image', help='The firmware image to be fuzzed', default="")
    parser.add_argument('-t', '--time', help='Fuzzing time', default="3m")
    res = parser.parse_args()
    try:
        image = res.image
        tmz = res.time
    except:
        print("The information provided is not enough")
        sys.exit(1)

    if "m" in tmz:
        timeout = int("".join(filter(str.isdigit, tmz))) * 60
    elif "h" in tmz:
        timeout = int("".join(filter(str.isdigit, tmz))) * 3600
    else:
        timeout = int("".join(filter(str.isdigit, tmz)))

    if not timeout:
        sys.exit(1)

    print(f"Will fuzz for {timeout} seconds")
    
    data = []
    fw_init_point = get_ifin_stock(image)
    # Set the data for fuzzer
    out_fuzz_dir = create_directories(image)
    fuzz_data = FuzzData(image, out_fuzz_dir, 0, timeout, fw_init_point)
    data.append(fuzz_data)
    
    # Fuzz
    for fuzz_data in data:
        start_fuzz(fuzz_data)
