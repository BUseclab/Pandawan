#!/usr/bin/env python3


import sys
import subprocess



if __name__ == "__main__":

    ### Get the firmae dir, the image kernel, mips version, and the image dir

    firmae_dir = sys.argv[1]
    kern_path = sys.argv[2]
    arch = sys.argv[3]
    image_dir = sys.argv[4]
    scratch_dir = sys.argv[5]
    firmsolo_dir = sys.argv[6]
    
    print("Firmsolo dir", firmsolo_dir)
    sys.path.append(firmsolo_dir)
    # Import the custom utils
    globals()["cu"] = __import__("custom_utils")

    upstream_dir = image_dir + "/upstream/"
        
    binaries_path = firmae_dir + "/firmsolo_binaries/"
    binaries_path_old = firmae_dir + "/binaries/"

    kernel = kern_path.split("/")[-1]
    
    res = ""
    
    cmd0 = 'file {0}/bin/busybox | grep "rel2"'.format(image_dir)
    try:
        res = subprocess.check_output(cmd0,shell=True).decode("utf-8")
    except:
        pass
    
    print("Arch", arch, "Kernel", kernel)
    
    if arch == "mipseb" or arch == "mipsel":
        if arch == "mipseb":
            end = "be"
        else:
            end = "le"

        if res == "":
            vers = "I"
        else:
            vers = "II"
    
        if vers == "I":
            if arch == "mipsel":
                version = "r1_mipsel"
            else:
                version= "r1_mips"
        else:
            if arch == "mipsel":
                version = "r2_mipsel"
            else:
                version= "r2_mips"
        
    if kernel < "linux-2.6.33":
        if "armel" not in arch:
            fl = "mips_old"
    else:
        if "armel" not in arch:
            fl = "mips_new"
    
    if kernel < "linux-2.6.36":
        if "armel" in arch:
            fl = "armel_old"
    else:
        if "armel" in arch:
            fl = "armel_new"
    
    if "armel" not in arch:
        print("Saving MIPS data to image dir")
        with open(image_dir + "../image_data","w") as f:
            f.write(vers+"\n")
            f.write(arch+"\n")
            f.write(kernel+"\n")
    if "armel" in arch:
        print("Saving ARM data to image dir")
        with open(image_dir + "../image_data","w") as f:
            f.write("None\n")
            f.write(arch+"\n")
            f.write(kernel+"\n")
    
    if "armel" not in arch:
        cmd1 = "cp {0}/console/{3}/console_{1} {2}/firmadyne/console".format(binaries_path,version,image_dir,fl)

        print("Console",cmd1)
        subprocess.run(cmd1,shell=True)

        cmd2 = "cp -r {0}/libnvram/{2}/{3}/* {1}/firmadyne/".format(binaries_path, image_dir,fl, end)

        print("Libnvram",cmd2)
        subprocess.run(cmd2,shell=True)

        ## Now copy the fuzzing agent to the filesystem
        cmd3 = f"cp {cu.tafl_lsf_dir}/pandawan/{fl}/{end}/driver {image_dir}/fuzzing/" 
        print("Fuzzing Agent",cmd3)
        subprocess.run(cmd3,shell=True)
    else:
        bindir = fl
        if arch == "armelv6":
            binaries_path = binaries_path_old
            bindir = "armel"
        
        if fl == "armel_new":
            cmd1 = "cp {}/console.armel {}/firmadyne/console".format(binaries_path_old, image_dir)
        else:
            cmd1 = "cp {0}/console/armel/console.armel_old {1}/firmadyne/console".format(binaries_path,image_dir,bindir)

        print("Console",cmd1)
        subprocess.run(cmd1,shell=True)

        cmd2 = "cp -r {0}/libnvram/{2}/* {1}/firmadyne/".format(binaries_path,image_dir, fl)

        print("Libnvram",cmd2)
        subprocess.run(cmd2,shell=True)

        ## Now copy the fuzzing agent to the filesystem
        cmd3 = f"cp {cu.tafl_lsf_dir}/pandawan/{fl}/driver {image_dir}/fuzzing/" 
        print("Fuzzing Agent",cmd3)
        subprocess.run(cmd3,shell=True)
