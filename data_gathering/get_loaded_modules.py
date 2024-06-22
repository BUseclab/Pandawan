#!/usr/bin/env python3


import os,sys
import pickle
import traceback
currentdir = os.path.dirname(os.path.realpath(__file__))
parentdir = os.path.dirname(currentdir)
import paths as pt
sys.path.append(pt.firmsolo_dir)
import custom_utils as cu
import re

tools = ["pandawan", "firmsolo"]

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
        size = data[2]

        diff_a1 = err_addr - addr

        if diff_a1 > 0:
            if diff_a1 < min_diff_err:
                min_dif_err = diff_a1
                where_err = mod
    return where_err

def get_static_crash_mod_info(serial_output, arch, crashing_module = None):
    crashing_mod = []
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

def get_modules(result, custom, image, system):
    total = {}
    not_loaded = {}
    prev_insmod = None
    for line in result:
        if "Module_name" in line:
            nl = line.split("Module_name: ")[1]
            tokens = nl.split()
            module_name = tokens[0] + ".ko"
            if prev_insmod:
                if module_name != prev_insmod:
                    total[prev_insmod].append(module_name)
            else:
                if module_name not in total:
                    total[module_name] = [1]
                else:
                    total[module_name][0] += 1
            prev_insmod = None
        if "insmod:" in line:
            mod = line.split(":")[1].split(" ")[-1].split("/")[-1].strip("'")
            if mod not in not_loaded and mod in custom:
                if mod.replace("-","_") in not_loaded:
                    continue
                else:
                    not_loaded[mod] = 1
                if mod not in total and mod.replace("-","_") not in total:
                    total[mod.replace("-","_")] = [1]
        if "relocation overflow" in line:
            mod = line.split(":")[0].split(" ")[-1] + ".ko"
            if mod not in not_loaded and mod in custom:
                if mod.replace("-","_") in not_loaded:
                    continue
                else:
                    not_loaded[mod] = 1
                if mod not in total and mod.replace("-","_") not in total:
                    total[mod.replace("-","_")] = [1]

        if "Unknown symbol" in line or "unknown symbol" in line:
            mod = line.split(" ")[0].strip(":") +".ko"
            if mod == "modprobe.ko" or mod == "insmod.ko" or mod == "rmmod.ko":
                continue
            if mod not in not_loaded and mod in custom:
                if mod.replace("-","_") in not_loaded:
                    continue
                else:
                    not_loaded[mod] = 1
                if mod not in total and mod.replace("-","_") not in total:
                    total[mod.replace("-","_")] = [1]
        if "register_chrdev_region err=" in line:
            mod = module_name
            if mod == "modprobe.ko" or mod == "insmod.ko" or mod == "rmmod.ko":
                continue
            if mod not in not_loaded and mod in custom:
                if mod.replace("-","_") in not_loaded:
                    continue
                else:
                    not_loaded[mod] = 1
                if mod not in total and mod.replace("-","_") not in total:
                    total[mod.replace("-","_")] = [1]

    return total, not_loaded

def read_pickle(fl):
    result = []
    try:
        with open(fl,"rb") as f:
            result = pickle.load(f)
    except:
        pass
    return result

def get_bad(mode, image):
    bad_custom_path = cu.loaded_mods_path + "{1}/crashed_modules_{0}.pkl".format(mode, image)
    bad_upstream_path = cu.loaded_mods_path + "{1}/crashed_modules_upstream_{0}.pkl".format(mode, image)
    
    try:
        bad_custom = cu.read_pickle(bad_custom_path)
    except:
        bad_custom = []
    try:
        bad_upstream = cu.read_pickle(bad_upstream_path)
    except:
        bad_upstream = []

    return bad_custom, bad_upstream

def get_fs_loaded(image, system):
    cu.loaded_mods_path = f"{pt.output_dir}/{system}/Loaded_Modules/"
    fs_loaded_mods_path = cu.loaded_mods_path + "{0}/{0}_ups_subs.pkl".format(image)
    
    try:
        fs_loaded_mods = cu.read_pickle(fs_loaded_mods_path)
    except:
        print(traceback.format_exc())
        fs_loaded_mods = [[]]

    return fs_loaded_mods[0]

def get_subs(path):
    subbed_mods = []
    try:
        data = cu.read_pickle(path)
        loaded = data[0]
        subs = data[1]
        core_subs = data[2]
        all_subs = subs + core_subs

        cust_path, upstr_path, subbed_mods = zip(*all_subs)

    except:
        core_subs = []
        pass
    
    return subbed_mods

def get_image_data(img, system):
    cu.loaded_mods_path = f"{pt.output_dir}/{system}_results/Loaded_Modules/"
    custom_path = cu.loaded_mods_path + "{0}/{0}_ups_subs.pkl".format(img)
    cu.img_info_path = f"{pt.output_dir}/{system}_results/Image_Info/"
    img_info = cu.img_info_path + "{0}.pkl".format(img)
    
    # Get the info for the Image
    infoz = cu.read_pickle(img_info)
    try:
        custom_mod_paths = infoz["modules"]
        arch = infoz["arch"]
    except:
        print(f"There is no info for image {image} and system {system}. Did you run the experiments.")
        print(traceback.format_exc())
        return [],[], None
    
    custom_mods = list(map(lambda x:x.split("/")[-1].replace(".ko",""),custom_mod_paths))

    # Get all the subs if the mode supports them 
    subs = []
    subs  = get_subs(custom_path)

    return custom_mods, subs, arch

class LoadedKmods:
    def __init__(self,img,system):
        self.img = img
        self.system = system
        self.custom, self.subs, self.arch = get_image_data(img, system)
    
    def filter_mods(self, total_mods, segfaulted, not_loaded, subbed, deleted):
        
        if self.custom == []:
            return None,None

        load_num = 0
        tot_custom = 0
        for mod in total_mods:
            if mod.replace(".ko","") in self.custom or mod.replace("_","-").replace(".ko","")  in self.custom:
                if len(total_mods[mod]) > 1:
                    tot_custom += len(total_mods[mod][1:])
                else:
                    tot_custom += 1
                if mod not in segfaulted and mod.replace("_","-") not in segfaulted:
                    if mod not in self.subs and mod.replace("_","-") not in self.subs:
                        if mod not in subbed and mod.replace("_","-") not in subbed:
                            if mod not in deleted and mod.replace("_","-") not in deleted: 
                                load_num += 1

        load_num -= len(not_loaded)

        return tot_custom,load_num

    def get_total_modules(self, subbed, deleted):
        if self.system in subbed:
            subbed_mods = subbed[self.system]
        else:
            subbed_mods = []

        if self.system in deleted:
            deleted_mods = deleted[self.system]
        else:
            deleted_mods = []

        total_mods = 0
        loaded_mods = 0
        segf_mods = 0

        qemu_log = f"{pt.output_dir}/{self.system}_results/scratch/{self.img}/qemu.final.serial.log"
        result = []
        try:
            result = cu.read_file(qemu_log)
        except:
            return total_mods, loaded_mods, segf_mods

        total_modules, not_loaded = get_modules(result, self.custom, self.img, self.system)

        crashing_mod = get_static_crash_mod_info(result, self.arch, None)
        if crashing_mod != None:
            segf = [crashing_mod + ".ko"]
        else:
            segf = []

        total_custom =0
        loaded_custom = 0
        total_custom,loaded_custom = self.filter_mods(total_modules, segf, not_loaded, subbed_mods, deleted_mods)
        
        total_mods = total_custom
        loaded_mods = loaded_custom
        segf_mods = len(segf)
            
        return total_mods, loaded_mods, segf_mods

def get_the_pw_subbed_del_mods(image):
    
    subbed_mods = {}
    deleted_mods = {}
    for tool in tools:
        subbed_mods[tool] = set()
        deleted_mods[tool] = set()
        
        cu.img_info_path = f"{pt.output_dir}/{tool}_results/Image_Info/"
        try:
            info = cu.get_image_info(image, "all")
        except:
            print(f"There is no available info ({image}.pkl) in {pt.output_dir}/{tool}_results/Image_Info/. Did you run the experiments for system {tool}?")
            continue

        all_modules = len(info['modules'])
        # Subbed and deleted crashed modules found by Pandawan's custom crash solving mechanism 
        if 'pandawan_dels_custom' in info:
            subs = info['pandawan_subs']
            dels_custom = info['pandawan_dels_custom']
            dels_upstream = info['pandawan_dels_upstream']
        else:
            subs = []
            dels_custom = []
            dels_upstream = []
    
        for sub in subs:
            subbed_mod = sub[2]
            if subbed_mod not in dels_custom and subbed_mod not in dels_upstream:
                if image not in subbed_mods:
                    subbed_mods[tool] = set()
                subbed_mods[tool].add(subbed_mod)
        
        for mod in dels_custom:
            if image not in deleted_mods:
                deleted_mods[tool] = set()
            deleted_mods[tool].add(mod)
    
    return subbed_mods, deleted_mods, all_modules

def get_image_loaded_mods(image):
    
    subbed_mods, deleted_mods, all_modules = get_the_pw_subbed_del_mods(image)
    
    all_mods = {}
    all_loaded = {}
    all_segf = {}
    
    for tool in tools:
        all_mods[tool] = 0
        all_loaded[tool] = 0
        all_segf[tool] = 0
    
        try:
            img_obj = LoadedKmods(image,tool)
        except:
            print("There is no information about the Loaded Kernel Modules for image", image, "and system", tool)
            continue

        t_c, t_l, t_b = img_obj.get_total_modules(subbed_mods, deleted_mods)

        all_mods[tool] = t_c
        all_loaded[tool] = t_l
        all_segf[tool] = t_b
    
    return all_modules, all_loaded, all_segf
