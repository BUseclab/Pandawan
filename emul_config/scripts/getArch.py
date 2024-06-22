#!/usr/bin/env python3

import sys
import tarfile
import subprocess

firmsolo_dir = sys.argv[2]
sys.path.append(firmsolo_dir)
import custom_utils as cu

archMap = {"MIPS64":"mips64", "MIPS":"mips", "ARM64":"arm64", "ARM":"arm", "Intel 80386":"intel", "x86-64":"intel64", "PowerPC":"ppc", "unknown":"unknown"}

endMap = {"LSB":"el", "MSB":"eb"}

def getArch(filetype):
    for arch in archMap:
        if filetype.find(arch) != -1:
            return archMap[arch]
    return None

def getEndian(filetype):
    for endian in endMap:
        if filetype.find(endian) != -1:
            return endMap[endian]
    return None

infile = sys.argv[1]
base = infile[infile.rfind("/") + 1:]
iid = base[:base.find(".")]

outdir = sys.argv[3]
tar = tarfile.open(infile, 'r')

infos = []
fileList = []
try:
    for info in tar.getmembers():
        if any([info.name.find(binary) != -1 for binary in ["/busybox", "/alphapd", "/boa", "/http", "/hydra", "/helia", "/webs"]]):
            infos.append(info)
        elif any([info.name.find(path) != -1 for path in ["/sbin/", "/bin/"]]):
            infos.append(info)
        fileList.append(info.name)

    with open(f"{outdir}/scratch/" + iid + "/fileList", "w") as f:
        for filename in fileList:
            try:
                f.write(filename + "\n")
            except:
                continue

    for info in infos[::-1]:
        tar.extract(info, path="/tmp/" + iid)
        filepath = "/tmp/" + iid + "/" + info.name
        filetype = subprocess.check_output(["file", filepath]).decode()

        arch = getArch(filetype)
        endian = getEndian(filetype)

        if arch and endian:
            with open(f"{outdir}/scratch/" + iid + "/fileType", "w") as f:
                f.write(filetype)

                break
        
    info = cu.get_image_info(iid, "all")
    arch = info['arch']
    endian = info['endian']
    if endian == "little endian":
        archend = arch + "el"
    else:
        archend = arch + "eb"

    print(archend)

    subprocess.call(["rm", "-rf", "/tmp/" + iid])

except:
    info = cu.get_image_info(iid, "all")
    arch = info['arch']
    endian = info['endian']
    if endian == "little endian":
        archend = arch + "el"
    else:
        archend = arch + "eb"

    print(archend)
