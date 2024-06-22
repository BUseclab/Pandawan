#!/usr/bin/env python3
import subprocess as sb
import traceback
import time
import sys, os

import paths as pt
sys.path.append(pt.firmsolo_dir)
import custom_utils as cu        
from firmsolo import FirmSolo

from kernel_profiles.gen_kernel_profiles import create_profile
import ast
import argparse as argp
from emul_config.scripts.erase_bad_modules import do_delete_the_modules
from oracle.oracle import Oracle
from data_gathering.get_bb_mods_avg import collect_kmod_coverage
from data_gathering.get_loaded_modules import get_image_loaded_mods
from data_gathering.get_bb_avg import get_user_bbs

data_dirs = ["results", "Loaded_Modules", "Image_Info", "scratch", "logs"]
files_to_patch = [f"{pt.pandawan_dir}/pandawan_pypanda.py", f"{pt.pandawan_dir}/emul_config/pandawan.config"]

def do_comparison(image):
    user_coverage = None
    progs = None
    try:
        user_coverage, progs = get_user_bbs(image)
    except:
        print("Something when wrong when collecting the user coverage for image", image)
    
    kmod_coverage = None
    try:
        kmod_coverage = collect_kmod_coverage(image)
    except:
        print("Something when wrong when collecting the KO coverage for image", image)
    
    all_mods = None    
    loaded_mods = None
    persistent_crashed = None
    
    try:
        all_mods, loaded_mods, persistent_crashed = get_image_loaded_mods(image)
    except:
        print("Something when wrong when collecting the loaded KOs for image", image)
    
    print(f"Metrics for image {image} across the compared re-hosting systems")
    for sys in ["pandawan", "firmsolo", "firmae", "firmadyne"]:
        print(f"System: {sys}")
        try:
            if user_coverage and progs:
                exec_progs = progs[sys]
                exec_bbs = user_coverage[sys]
                print(f"\tExecuted programs: {exec_progs}, Unique BBs: {exec_bbs}")
            else:
                print(f"\tExecuted programs: n/a, Unique BBs: n/a")
        except:
            print(f"\tExecuted programs: error, Unique BBs: error")

        try:
            if all_mods and loaded_mods and persistent_crashed:
                if sys not in ["firmae", "firmadyne"]:
                    all_modules = all_mods
                    loaded_modules = loaded_mods[sys]
                    p_crashed = persistent_crashed[sys]
                    # In general we should not have persistent crashes because Pandawan accounts for these
                    # If there are any its probably a bug in the crashed modules detection logic
                    print(f"\tTotal KOs: {all_modules}, Loaded KOs: {loaded_modules}, Persistent crashes: {p_crashed}")
                else:
                    print(f"\tSystem {sys} does not load KOs")
            else:
                    print(f"\tTotal KOs: n/a, Loaded KOs: n/a, Persistent crashes: n/a")
        except:
            print(f"\tTotal KOs: error, Loaded KOs: error, Persistent crashes: error")

        try:
            if kmod_coverage:
                if sys not in ["firmae", "firmadyne"]:
                    ko_bbs = kmod_coverage[sys]
                    print(f"\tUnique KO TBs: {ko_bbs}")
                else:
                    print(f"\tSystem {sys} does not execute KO code")
            else:
                    print(f"\tUnique KO TBs: n/a")
        except:
            print(f"\tUnique KO TBs: error")

def patch_paths(system):
    if system in ["pandawan", "firmsolo"]:
        for indx,fl in enumerate(files_to_patch):
            if indx == 0:
                with open(fl, "r") as f:
                    lines = f.readlines()
                
                if lines[6] != "\n":
                    continue
                tmp_indx = 6
                lines.insert(tmp_indx, f"pandawan_dir = \"{pt.pandawan_dir}\"\n")
                tmp_indx += 1
                lines.insert(tmp_indx, f"sys.path.append(pandawan_dir)\n")
                
                with open(fl, "w") as f:
                    f.writelines(lines)
            if indx == 1:
                with open(fl, "r") as f:
                    lines = f.readlines()
                
                lines[28] = f"FIRMAE_DIR=\"{pt.pandawan_dir}/emul_config/\"\n"
                lines[30] = f"FS_OUT_DIR=\"{pt.output_dir}/\"\n"
                lines[32] = f"FS_SCRIPT_DIR=\"{pt.firmsolo_dir}/\"\n"
                
                with open(fl, "w") as f:
                    f.writelines(lines)

def create_system_out_dirs(system):
    cmd = f"mkdir -p {cu.abs_path}/{system}_results/"
    try:
        sb.run(cmd, shell=True)
    except:
        # the directories are already there?
        pass

def mountImage(targetDir):
    loopFile = sb.check_output(['bash', '-c', 'source ./emul_config/scripts/pandawan.config && add_partition %s/image.raw' % targetDir]).decode().strip()
    sb.run('mount %s %s/image > /dev/null' % (loopFile, targetDir), shell=True)
    time.sleep(1)
    return loopFile

def umountImage(targetDir, loopFile):
    sb.run('umount %s/image > /dev/null' % targetDir, shell=True)
    sb.check_output(['bash', '-c', 'source ./emul_config/scripts/pandawan.config && del_partition %s' % loopFile])

class Pandawan(FirmSolo):
    def __init__(self, image_name, plugin_opts, system):
        self.plugin_opts = plugin_opts
        self.system = system
        # If the image string is an ID we assume that the image is already extracted
        # Else extract it using the extractor from FirmAE
        if not image_name.isnumeric():
            iids = os.listdir(f"{cu.abs_path}/scratch/")
            iid = iids.sort()[-1]
            cwd = os.getcwd()
            os.chdir("./emul_config/")
            result = self.__run_config(image_name, iid, 0)
            if not result:
                return
            os.chdir(cwd)
            super().__init__(iid)
        else:
            super().__init__(image_name)
        
        self.scratch_dir = f"{cu.abs_path}/scratch/{self.image}/"
        sb.run(["mkdir", "-p", f"{self.scratch_dir}/"])
        self.times_run_dslc = 0
        self.times_run_pw_subs = 0

    # TODO: change this.
    # It should not copy every time the results for each system
    # every system should have its own dir from the beginning
    def save_system_data(self):
        for dir in data_dirs:
            target = self.image
            if dir == "Image_Info":
                target = f"{self.image}.pkl"
            if dir == "logs":
                target = ""
            cmd = f"rsync -a {cu.abs_path}/{dir}/{target} {cu.abs_path}/{self.system}_results/{dir}/"
            try:
                sb.run(cmd, shell=True)
            except:
                print(f"Pandawan could not save the data (from dir {dir}) for {self.system} and {self.image} in {cu.abs_path}/{self.system}_results/{dir}. Are the directories present?")
    
    def invoke_oracle(self):
        oracle = Oracle(self.image)
        oracle.get_safe_opts()
    def stop_pandawan(self):
        res = ""
        try: 
            pid_to_kill = "ps aux | grep run.py"
            res = sb.check_output(pid_to_kill, shell=True).decode("utf-8")
        except Exception as e:
            pass

        if res != "":
            results = res.split("\n")
            for rs in results:
                if "grep" not in rs:
                    if rs.split() == []:
                        continue
                    pid = int(rs.split()[1])
                    print("Killing pid",pid)
            try:
                sb.run(["kill", "-2", f"{pid}"])
                time.sleep(5)
                sb.run(["kill", "-9", f"{pid}"])
            except Exception as e:
                pass

            time.sleep(2)
    
    def analyze_image(self, do_subs, all_steps, steps, global_timeout, firmsolo, firmae, firmadyne):

        # Run FirmSolo for the first time
        if all_steps or "s1" in steps:
            self.run_stage1()
        # We need the upstream modules so we compile once
        if (all_steps or "s2a" in steps) and (not firmae and not firmadyne):
            if firmsolo:
                self.run_stage2a(None, [], False, False, False)
            else:
                self.run_stage2a(None, [], False, False, True)
        ## Run Oracle here to add the safe options used in general
        ## by IoT firmware images. Then recompile the kernel with these options
        if (all_steps or "oracle" in steps)  and (not firmae and not firmadyne):
            self.invoke_oracle()
            if firmsolo:
                self.run_stage2a(None, [], False, False, False)
            else:
                self.run_stage2a(None, [], False, False, True)
        
        time.sleep(2)
        if (all_steps or "s2b" in steps) and (not firmae and not firmadyne):
            self.run_stage2b()
        
        if (all_steps or "s2c" in steps) and (not firmae and not firmadyne):
            print("Running DSLC for", self.image, "with a timeout of 2 hours")
            if firmsolo:
                try:
                    cmd = [f"{pt.firmsolo_dir}/stage2c/dslc.py", "--image_id", self.image]
                    sb.run(cmd, timeout=7200)
                except:
                    print("DSLC reached its timeout...Aborting")
                    time.sleep(2)
                    self.run_stage2a(None, [], False, False, False)
                    self.run_stage2b()
            else:
                try:
                    cmd = [f"{pt.firmsolo_dir}/stage2c/dslc.py", "--image_id", self.image, "--fi_opts", '"-p"']
                    sb.run(cmd, timeout=7200)
                except:
                    print("DSLC reached its timeout...Aborting")
                    time.sleep(2)
                    self.run_stage2a(None, [], False, False, True)
                    self.run_stage2b()

        time.sleep(2)
        ## Create a profile for the kernel
        if (all_steps or "script_config" in steps):
            if not firmae and not firmadyne:
                # Pandawan or FirmSolo
                create_profile(self.image, pt.pandawan_dir, pt.firmsolo_dir)
                cmd = f"{pt.pandawan_dir}/emul_config/run.sh -c \"\" {self.image} {pt.pandawan_dir}"
            elif firmae:
                # FirmAE
                cmd = f"{pt.firmae_dir}/run.sh -c \"\" {self.image} {pt.firmae_dir}"
            elif firmadyne:
                # Firmadyne
                info = cu.get_image_info(self.image, "all")
                if info['arch'] == "mips":
                    if info['endian'] == "little endian":
                        arch = "mipsel"
                    else:
                        arch = "mipseb"
                else:
                    arch = "armel"
                cmd = f"{pt.firmadyne_dir}/run.sh {self.image} {arch} {pt.firmadyne_dir}"

            # Create the PyPANDA scripts for the image
            try:
                sb.run(cmd, shell=True)
            except:
                print(f"Could not create PyPANDA scripts for image {self.image}")
                return

        time.sleep(5)
        if all_steps or "emul" in steps:
            done = False
            retries = 0
            while not done:
                cmd = f"timeout --preserve-status --foreground -s INT -k 60s {global_timeout}s {self.scratch_dir}/run.py \
                    {cu.abs_path}/scratch/ {cu.abs_path}/ {cu.abs_path}/scratch/ {self.plugin_opts}"
                try:
                    if retries > 4:
                        done = True
                        continue
                    
                    print("Running pandawan experiment in retry", retries)
                    proc = sb.run(cmd, shell=True, timeout=int(f"{global_timeout}") + 50)
                    
                    self.stop_pandawan()
                    # This should not happen, especially in ARM that do not have the networking
                    # configuration disabled
                    if proc.returncode == 137:
                        print("No output from pandawan")
                        print(traceback.format_exc())
                        self.stop_pandawan()
                        if retries <= 5:
                            print("Pandawan did not produce any output...Retrying emulation")
                            retries += 1
                            time.sleep(2)
                            continue

                    time.sleep(10)
                    if do_subs:
                        print("Doing substitutions!!!")
                        done = self.__do_subs(firmsolo)
                    else:
                        done = True
                    # If this happens, increase your global timeout
                    if proc.returncode == 124:
                        print("Pandawan reached global timeout...Stopping current experiment")
                except sb.TimeoutExpired:
                    print("Pandawan reached global timeout...Stopping current experiment")
                    self.stop_pandawan()
                    done = True
                    continue
                except KeyboardInterrupt:
                    print("Pandawan stopped by user. Exiting....")
                    self.stop_pandawan()
                    done = True
                    continue
                except:
                    print(traceback.format_exc())
                    print("Something went unexpectedly wrong with Pandawan's emulation...Aborting")
                    self.stop_pandawan()
                    done = True    
                    continue
                
                if not firmae and not firmadyne:
                    print(f"Ran FirmSolo's dslc {self.times_run_dslc} times and Pandawan's subs {self.times_run_pw_subs} times")

        # Save the results for the respective system and image in the systems outdir
        print("Saving system/image data...")
        self.save_system_data()

    def get_arch(self):
        info = cu.get_image_info(self.image, "all")
        
        arch= info["arch"]
        endian = info["endian"]

        if arch == "mips":
            if endian == "little endian":
                archend = "mipsel"
            else:
                archend = "mipseb"
        else:
            archend = "armel"
        
        return archend
    
    def recreate_image(self, do_pw_sub):
        # First create the firmware filesystem with Firmadyne
        if do_pw_sub:
            verdict = "yes"
        else:
            verdict = "no"
        
        loopFile = mountImage(self.scratch_dir)
        do_delete_the_modules(self.image, f"{self.scratch_dir}/image/", verdict, f"{pt.firmsolo_dir}")
        umountImage(self.scratch_dir, loopFile)

        # Then create again the profile for the kernel if DSLC ran
        if not do_pw_sub:
            create_profile(self.image)
        
        return
    
    def run_dslc_and_compile(self, firmsolo):
        serial_out = f"{self.scratch_dir}/qemu.final.serial.log"
        
        if firmsolo:
            enable_pandawan = False
        else:
            enable_pandawan = True

        # Run DSLC using Pandawan's emulation output and capture the solution
        # printed if any
        try:
            lines = cu.read_file(f"{cu.log_path}/pandawan_dslc.out")
        except:
            lines = []
        # Keep track of the length to see if we found a new solution
        initial_len = len(lines)
        
        try:
            print("Running Pandawan DSLC for image", self.image, "for 2 hours")
            if not enable_pandawan:
                cmd = [f"{pt.firmsolo_dir}/stage2c/dslc.py", "--image_id", self.image, "--fi_opts", '"-e"', "--serial_out", serial_out]
            else:
                cmd = [f"{pt.firmsolo_dir}/stage2c/dslc.py", "--image_id", self.image, "--fi_opts", '"-e -p"', "--serial_out", serial_out]
            sb.run(cmd, timeout=7200)
        except:
            self.run_stage2a(None, [], False, False, True)
            self.run_stage2b()
            return False
        # Run DSLC using the Pandawan output

        # Read again the result
        try:
            lines = cu.read_file(f"{cu.log_path}/pandawan_dslc.out")
        except:
            lines = []

        if len(lines) == initial_len:
            print(f"No DSLC solution found for {self.image}")
            return False
        # Parse the solution if any

        last_line = lines[-1]
        if "No solution" in last_line:
            print(f"No DSLC solution found for {self.image}")
            return False
        
        print("Pandawan dslc found solution:", last_line)
        try:
            sol_opts = ast.literal_eval(last_line)
        except:
            sol_opts = None
        
        if sol_opts:
            # Save the solution found by DSLC in the general image data
            self.save_firmadyne_dslc(sol_opts)
            # Now we have to recompile the kernel with the new solutions found by DSLC
            self.run_stage2a(None, [], False, True, True)
            return True #Success
        
        return False #Failure

    def __run_config(image_name, iid, mode):

        if mode == 0:
            cmd = f"./run.sh -e {image_name} {iid}"
        else:
            cmd = f"./run.sh -c {image_name} {iid}"

        try:
            sb.run(cmd, shell = True)
        except:
            print(f"Running FirmAE's networking and script configuration logic for {image_name} failed!")
            return False
        return True

    def __do_subs(self, firmsolo):
        # Import the class that will give us the crashing modules
        from data_gathering.get_crashed_modules import CrashedMods
        
        img = CrashedMods(self.image, "ups_subs", "", pt.firmsolo_dir)
        pandawan_current_crashed, _ = img.get_crashing_modules()
        print("The crashing modules for image", self.image, "are", pandawan_current_crashed)
        done = False
        if pandawan_current_crashed != set():
            result = False
            result = self.run_dslc_and_compile(firmsolo)
            self.times_run_dslc += 1
            if result:
                self.recreate_image(False)
            else:
                self.times_run_pw_subs += 1
                self.recreate_image(True)
        else:
            done = True
            
        return done

def main():
    
    parser = argp.ArgumentParser(description='Run Pandawan')
    parser.add_argument('image', type=str, help='Either the path to the firmware image or the ID of an extracted firmware image')
    parser.add_argument('-g', '--global_timeout', type=int, help='Global timeout in seconds for the pandawan emulation', default=1800)
    parser.add_argument('-s', '--do_subs', help='Do the pandawan substitutions', action='store_true')
    parser.add_argument('-a', '--all', help='Run all the analysis steps', action='store_true')
    parser.add_argument('-t', '--steps', nargs="*", help='Which of the analysis steps to run? ([s1, s2a, s2b, s2c, oracle, script_config, emul])', required=False)
    parser.add_argument('-f', '--firmsolo', help='Compile the stock FirmSolo kernels without Pandawans augmentation', action='store_true')
    parser.add_argument('-e', '--firmae_stock', help='Run FirmAE stock', action='store_true')
    parser.add_argument('-d', '--firmadyne_stock', help='Run Firmadyne stock', action='store_true')
    parser.add_argument('-p', '--plugin_opts', type=str, help='The pypanda plugins to enable. Provided as "\-f 300 \-s \-t \-c" (f:ficd, s:syscalls_logger, t:syscalltokmodtracer, c:coverage)', default="")
    parser.add_argument('-c', '--comparison', help='Print the comparison metrics (User programs, User coverage (BBs), KOs loaded, KO coverage (BBs))', action='store_true')
    
    
    image = parser.parse_args().image
    timeout = parser.parse_args().global_timeout
    do_subs = parser.parse_args().do_subs
    all_steps = parser.parse_args().all
    steps = parser.parse_args().steps
    firmsolo = parser.parse_args().firmsolo
    firmae = parser.parse_args().firmae_stock
    firmadyne = parser.parse_args().firmadyne_stock
    plugin_opts= parser.parse_args().plugin_opts
    comparison= parser.parse_args().comparison

    systems_chosen = 0
    for sys in [firmsolo, firmae, firmadyne]:
        if sys:
            systems_chosen += 1
    if systems_chosen > 1:
        print("Please enable only one (or zero to choose pandawan) of the system selection options -f, -e, -d")
        return

    if firmsolo:
        system = "firmsolo"
    elif firmae:
        system = "firmae"
    elif firmadyne:
        system = "firmadyne"
    else:
        system = "pandawan"
    
    patch_paths(system)
    create_system_out_dirs(system)
    
    if comparison:
        do_comparison(image)
        return
    
    pandawan = Pandawan(image, plugin_opts, system)
    if not steps and not all_steps:
        print("You have to set one of the options steps or all_steps (-t, -a) before running")
        return
    pandawan.analyze_image(do_subs, all_steps, steps, timeout, firmsolo, firmae, firmadyne)

if __name__ == "__main__":
    main()
