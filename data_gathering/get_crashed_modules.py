#!/usr/bin/env python3


import os,sys
import traceback
currentdir = os.path.dirname(os.path.realpath(__file__))
parentdir = os.path.dirname(currentdir)
import re

broken_modules = []

def static_find_crashing_mod(module_data, error_addr, arch):
    if "mips" in arch:
        kernel_addr = int(0x80000000)
    elif "arm" in arch:
        kernel_addr = int(0xc0000000)

    min_diff_err = 5000000000
    where_err = ""
    err_addr = int(error_addr[0], 16)

    diff_a1 = err_addr - kernel_addr
    if diff_a1 > 0:
        if diff_a1 < min_diff_err:
            min_diff_err = diff_a1
            where_err = "kernel"
    for data in module_data:
        mod = data[0]
        addr = int(data[1], 16)

        diff_a1 = err_addr - addr

        if diff_a1 > 0:
            if diff_a1 < min_diff_err:
                min_diff_err = diff_a1
                where_err = mod
    return where_err

def get_static_crash_mod_info(serial_output, arch, crashing_module = None):
    module_data = []
    error_data = []
    err_addr = []

    error_found = False
    module_name = None
    seen_oops = False

    for line in serial_output:
        if "Module_name" in line:
            error_found = False
            tk = line.split("Module_name:")[1]
            tokens = tk.split()
            if not module_name:
                module_name = tokens[0]
            module_data.append([module_name, tokens[2], tokens[4]])
            current_module = module_name
            module_name = None
        if "Oops" in line or "Kernel bug detected" in line or "BUG:" in line:
            seen_oops = True
        if "------------[ cut here ]------------" in line:
            seen_oops = True
            error_found = False
            continue
        if "epc   :" in line and seen_oops == True:
            tokens = line.split()
            err_addr.append("0x" + tokens[2])
            error_found = True
            error_data.append(line)
            seen_oops = False
            continue
        if "pc :" in line and seen_oops == True:
            tokens = line.split()
            addr = "0x" + tokens[2].replace("[<","").replace(">]","")
            err_addr.append(addr)
            error_found = True
            error_data.append(line)
            seen_oops = False
            continue
        if error_found == True:
            error_data.append(line)

    if error_data == []:
        return None
    try:
        crashing_module = static_find_crashing_mod(module_data, err_addr, arch)
    except:
        print(traceback.format_exc())
        print("Something went bad")
    
    if crashing_module == "kernel" or crashing_module == "" or crashing_module == None:
        for ln in error_data:
            func_addresses = re.findall("(\[\<.*\>\])", ln)
            if func_addresses:
                address = ["0x" + func_addresses[0].split()[0].strip("[<>]")]
                if address == []:
                    continue
                crashing_module = static_find_crashing_mod(module_data, address, arch)
                if crashing_module != "kernel" and crashing_module != "":
                    break

    if crashing_module == "kernel" or crashing_module == "":
        return None
    if crashing_module and crashing_module != "kernel":
        return crashing_module
    else:
        return None

def get_image_data(img,mode):
    img_info = cu.img_info_path + "{0}.pkl".format(img)
    
    infoz = cu.read_pickle(img_info)
    try:
        custom_mod_paths = infoz["modules"]
        arch = infoz["arch"]
    except:
        print("Cannot get image info for", img)
        print(traceback.format_exc())
        return [],[], None
    
    custom_mods = list(map(lambda x:x.split("/")[-1],custom_mod_paths))

    return custom_mods, arch

class CrashedMods:
    def __init__(self,img,mode,outfile, firmsolo_dir):
        sys.path.append(firmsolo_dir)
        # Import the custom utils
        globals()["cu"] = __import__("custom_utils")

        self.img = img
        self.mode = mode
        self.scratch = f"{cu.abs_path}/scratch/"
        self.img_dir = f"{self.scratch}/{img}/"
        self.outfile = outfile
        self.custom, self.arch = get_image_data(img, mode)
    
    def filter_mods(self, total_mods, segfaulted, not_loaded):

        if self.custom == []:
            return None,None
        
        print("Gathering kernel module data for image", self.img)
        print(self.custom)
        load_num = 0
        tot_custom = 0
        for mod in total_mods:
            if mod in self.custom or mod.replace("_","-") in self.custom:
                if len(total_mods[mod]) > 1:
                    tot_custom += len(total_mods[mod][1:])
                else:
                    tot_custom += 1
                if mod not in segfaulted and mod.replace("_","-") not in segfaulted:
                    if mod not in self.subs and mod.replace("_","-") not in self.subs:
                        load_num += 1

        load_num -= len(not_loaded)
        print("Image:",self.img, "Total modules:",tot_custom,"Loaded modules:",load_num)

        return tot_custom,load_num

    def get_crashing_modules(self, *args):
        crash_mod_dict = {}
        if not args:
            info = cu.get_image_info(self.img, "all")
        
            if 'pandawan_subs' in info:
                for sub in info['pandawan_subs']:
                    if self.img not in crash_mod_dict:
                        crash_mod_dict[self.img] = set()
                    crash_mod_dict[self.img].add(sub[2])
                for crashed in info['pandawan_dels_custom']:
                    if self.img not in crash_mod_dict:
                        crash_mod_dict[self.img] = set()
                    crash_mod_dict[self.img].add(crashed)

        qemu_log = self.img_dir + "/qemu.final.serial.log"
        result = []

        try:
            result = cu.read_file(qemu_log)
        except:
            return set(), set()

        segf = set()
        crashing_mod = get_static_crash_mod_info(result, self.arch, None)
        if crashing_mod != None:
            segf.add(crashing_mod + ".ko")
        
        if crashing_mod not in [None, "", "kernel"]:
            if crashing_mod not in broken_modules:
                broken_modules[crashing_mod] = [self.img]
            else:
                broken_modules[crashing_mod].append(self.img)
        
        if self.img not in crash_mod_dict:
            crash_mod_dict[self.img] = set()

        return segf, crash_mod_dict[self.img]
