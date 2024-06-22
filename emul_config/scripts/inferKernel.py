#!/usr/bin/env python3

import sys
import os
import subprocess

IID = -1

IID = sys.argv[1]
scratch = sys.argv[2]
image_dir = sys.argv[3]

def ParseInit(cmd, out):
    for item in cmd.split(' '):
        if item.find("init=/") != -1:
            out.write(item + "\n")

def ParseCmd():
    if not os.path.exists(f"{scratch}" + IID + "/kernelCmd"):
        return
    with open(f"{scratch}" + IID + "/kernelCmd") as f:
        out = open("{}/{}/kernelInit".format(scratch, IID), "w")
        cmds = f.read()
        for cmd in cmds.split('\n')[:-1]:
            ParseInit(cmd, out)
        out.close()

if __name__ == "__main__":
    # execute only if run as a script
    kernelPath = f'{image_dir}' + IID + '.kernel'
    os.system("strings {} | grep \"Linux version\" > {}".format(kernelPath,
                                                                f"{scratch}" + IID + "/kernelVersion"))

    os.system("strings {} | grep \"init=/\" | sed -e 's/^\"//' -e 's/\"$//' > {}".format(kernelPath,
                                                                f"{scratch}" + IID + "/kernelCmd"))

    ParseCmd()
