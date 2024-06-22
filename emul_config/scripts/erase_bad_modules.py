#!/usr/bin/env python3

import sys,pickle
import subprocess
import traceback


extra_bad_modules = []

def get_subs(image):
    pickle_file = f"{cu.loaded_mods_path}{image}/{image}_ups_subs.pkl"
    subs = []
    
    try:
        info = cu.read_pickle(pickle_file)
        subs = info[1]
    except:
        print(traceback.format_exc())

    return subs

def get_bad_modules(bad_mod_path):

    with open(bad_mod_path,"rb") as f:
        bad_mods = pickle.load(f)

    return bad_mods

def erase_not_loaded_modules(image, image_dir):
    info = cu.get_image_info(image, "all")
    modules = info['modules']
    pickle_file = f"{cu.loaded_mods_path}{image}/{image}_ups_subs.pkl"
    loaded_modules = []
    subs = []
    try:
        info = cu.read_pickle(pickle_file)
        loaded_modules = info[0]
        subs = info[1]
    except:
        print(traceback.format_exc())
    
    print("Loaded_modules", loaded_modules)
    print("Subs", subs)
    for module in modules:
        module_name =  module.split("/")[-1]
        mod_name = module.split("/")[-1].replace(".ko","")
        if mod_name not in loaded_modules and mod_name not in subs:
            shipped_path = find_mod(module_name,image_dir, "custom")
            try:
                print("Truncating loaded module", shipped_path)
                open(f"{shipped_path}", "w").close()
                output = subprocess.check_output(["file",f"{shipped_path}"]).decode("utf-8")
                print(output)
            except:
                print("Module", module_name, "is already deleted")

def find_mod(mod,image_dir,m_type):
    
    result = ""
    try:
        res = subprocess.check_output("find {0} -name {1}".format(image_dir,mod),shell=True)
    except Exception as e:
        print(e)
        print("Could not find the module...",mod)
    
    output = res.decode("utf-8").split("\n")
    print (output)
    print("\n")
    if len(output) > 1 and m_type == "custom":
        for mod in output:
            if "upstream" in mod:
                continue
            result = mod
            break
    else:
        result = output[0]

    return result

def sub_mods(distrib_path, upstream_path):
    try:
        cmd = "sudo cp {0} {1}".format(upstream_path, distrib_path)
        res = subprocess.call(cmd,shell=True)
    except Exception as e:
        print(e)
        print("Could not substitute module", distrib_path)

def delete_modules(bad_mods, image_dir,m_type):

    for mod in bad_mods:
        mod_path = find_mod(mod,image_dir,m_type)
        if mod_path == "":
            continue
        print("Bad module",mod_path,"Type",m_type)
        try:
            res = subprocess.call("sudo rm "+ mod_path,shell=True)
        except Exception as e:
            print(e)
            print("Could not delete module",mod_path)

def sub_bad_mods(image, pandawan_bad_mods, image_dir, upstream_dir):
    info = cu.get_image_info(image, "all")
    if 'pandawan_subs' not in info:
        info['pandawan_subs'] = []
        info['pandawan_dels_custom'] = set()
        info['pandawan_dels_upstream'] = set()

    for mod in pandawan_bad_mods:
        print("Trying to sub mod",mod)
        shipped_path = find_mod(mod,image_dir, "custom")
        vanilla_path = find_mod(mod,upstream_dir, "upstream")
        print("Distributed subbed out",shipped_path)
        print("Upstream subbed in",vanilla_path)
        if shipped_path != "" and vanilla_path != "" and [shipped_path, vanilla_path, mod] not in info['pandawan_subs']:
            print("Substituting",mod)
            sub_mods(shipped_path,vanilla_path)
            info['pandawan_subs'].append([shipped_path, vanilla_path, mod])
        else:
            if mod not in info['pandawan_dels_custom']:
                info['pandawan_dels_custom'].add(mod)
            else:
                info['pandawan_dels_upstream'].add(mod)

    info_path = f"{cu.img_info_path}/{image}.pkl"
    cu.write_pickle(info_path, info)

def do_delete_the_modules(image, image_dir, delete_extra_mods, firmsolo_dir, pandawan_dir):
    sys.path.append(firmsolo_dir)
    # Import the custom utils
    globals()["cu"] = __import__("custom_utils")

    sys.path.append(pandawan_dir)
    from data_gathering.get_crashed_modules import CrashedMods

    upstream_dir = image_dir + "/upstream/"
    
    print("Image", image, "Image dir", image_dir)
    bad_custom_mod_path =f"{cu.loaded_mods_path}{image}/crashed_modules_ups_subs.pkl"
    bad_upstream_mod_path = f"{cu.loaded_mods_path}{image}/crashed_modules_upstream_ups_subs.pkl"
    timedout_custom_mod_path = f"{cu.loaded_mods_path}{image}/timed_out.pkl"
    timedout_upstream_mod_path = f"{cu.loaded_mods_path}/timed_out_upstream.pkl"
    bad_mods_shipped = []
    bad_mods_native = []

    img = CrashedMods(image, "ups_subs", "", firmsolo_dir)
    pandawan_crashed, _ = img.get_crashing_modules()

    try:
        bad_mods_shipped = get_bad_modules(bad_custom_mod_path)
        bad_mods_shipped.append("ag7100_mod.ko")
    except:
        print ("No bad distributed modules yet")

    try:
        bad_mods_native = get_bad_modules(bad_upstream_mod_path)
    except:
        print ("No bad upstream modules yet")

    try:
        timedout_shipped = get_bad_modules(timedout_custom_mod_path)
        bad_mods_shipped += timedout_shipped
    except:
        print ("No timed out distributed modules yet")

    try:
        timedout_mods_native = get_bad_modules(timedout_upstream_mod_path)
        bad_mods_native += timedout_mods_native
    except:
        print ("No timedout upstream modules yet")

    erase_not_loaded_modules(image, image_dir)

    print ("Distributed crashed modules")
    print (bad_mods_shipped)
    delete_modules(bad_mods_shipped, image_dir, "custom")

    print ("Upstream crashed modules")
    print (bad_mods_native)
    delete_modules(bad_mods_native,upstream_dir,"upstream")

    if delete_extra_mods == "yes":
        sub_bad_mods(image, pandawan_crashed, image_dir, upstream_dir)

    info = cu.get_image_info(image, "all")
    try:
        for mod in info['pandawan_subs']:
            print("Distributed subbed out", mod[0])
            print("Upstream subbed in", mod[1])
            print("Substituting",mod[2])
            if mod[2] in info['pandawan_dels_custom'] or mod[2] in info['pandawan_dels_upstream']:
                continue
            sub_mods(mod[0], mod[1])
    except:
        pass # There were no subs yet

    if 'pandawan_subs' in info:
        delete_modules(info['pandawan_dels_custom'], image_dir,"custom")
        delete_modules(info['pandawan_dels_upstream'], image_dir,"upstream")

    subs = get_subs(image)
    for sub in subs:
        tmp1 = sub[0].split("/")
        del tmp1[0]
        sub[0] = "/".join(tmp1)
        tmp2 = sub[1].split("/")
        del tmp2[0]
        sub[1] = "/".join(tmp2)
        custom_path = image_dir + sub[0]
        upstream_path = image_dir + sub[1].replace("/home/","/upstream/")
        module = sub[2]
        print("Substituting module",module)
        sub_mods(custom_path,upstream_path)
    
if __name__ == "__main__":
    image = sys.argv[1]
    image_dir = sys.argv[2]
    delete_extra_mods = sys.argv[3]
    firmsolo_dir = sys.argv[4]
    pandawan_dir = sys.argv[5]

    do_delete_the_modules(image, image_dir, delete_extra_mods, firmsolo_dir, pandawan_dir)

