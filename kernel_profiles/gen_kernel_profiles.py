#!/usr/bin/env python3


import os
import sys
import subprocess as sb
import traceback
from multiprocessing import Pool

def create_profile(image, pandawan_dir, firmsolo_dir):
    run_script = f"{pandawan_dir}/kernel_profiles/run.sh"
    sys.path.append(firmsolo_dir)
    # Import the custom utils
    globals()["cu"] = __import__("custom_utils")
    
    image_info = "{}{}/{}.pkl".format(cu.img_info_path, image, image)
    which_info = ["kernel", "arch"]
    info = cu.get_image_info(image,which_info)
    kernel, arch = info[0], info[1]

    kernel_path = "{}/{}/linux-{}/vmlinux".format(cu.result_dir_path, image, kernel)

    l_mods_path = "{}/{}/kernel-{}.conf".format(cu.loaded_mods_path, image, kernel)
    
    try:
        mkdir = f"mkdir {cu.loaded_mods_path}/{image}"
        res = sb.run( mkdir, shell=True)
    except:
        print(traceback.format_exc())

    cmd = "{} {} {}".format(run_script, kernel_path, l_mods_path)
    try:
        res = sb.run( cmd, shell=True)
    except:
        print(traceback.format_exc())

    with open(l_mods_path, "r")  as f:
        lines = f.readlines()
    
    for indx,line in enumerate(lines):
        if "task.per_cpu_offsets_addr =" in line:
            lines[indx] = "task.per_cpu_offsets_addr = 0\n"
            break

    lines = ["[{}]\n".format(image)] + lines

    with open(l_mods_path, "w")  as f:
        f.writelines(lines)

def main():
    
    image = sys.argv[1]
    
    create_profile(image)

if __name__ == "__main__":
    main()
