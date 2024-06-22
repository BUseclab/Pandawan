#!/usr/bin/env python3
import os
import sys
import subprocess
from pandare import Panda
import pickle

# Set These
pandawan_dir = "/Pandawan/"
bindir = "/FirmAE/binaries/"
scratch = f"/output/scratch/{IID}/"
image = scratch+"image.raw"
sys.path.append(pandawan_dir)

from plugins.pandawan.ficd import FwInitStopFinder
from plugins.pandawan.record_procs import RecordProcs
from plugins.pandawan.syscalltokmodtracer import KmodFuncTracer
import argparse as argp


# ARCHEND, NETARGS, IID, START_NET, STOP_NET, QEMU_NETWORK variables are injected into this file by makeNetwork

parser = argp.ArgumentParser(description='Enable Kernel Module Function Tracer Plugin')
parser.add_argument('image_dir', type=str, help='Directory that contains the file-system images')
parser.add_argument('data_dir', type=str, help='Directory that contains the kernel and the loaded module information')
parser.add_argument('result_dir', type=str, help='Directory that contains the emulation and analysis results')
parser.add_argument('-t','--kmod_trace', help='Enable the Syscall to Kernel Module Tracer plugin', action = 'store_true')
parser.add_argument('-f','--time_frame', type=int, help='Enable the Kernel Module Tracer plugin')
parser.add_argument('-s','--syscalls_logger', help='Enable syscalls_logger plugin', action = 'store_true')
parser.add_argument('-c','--coverage', help='Enable the coverage plugin', action = 'store_true')
parser.add_argument('-r','--record_procs', type=int, help='Record all procs')

trace = parser.parse_args().kmod_trace
time_frame = parser.parse_args().time_frame
record_procs = parser.parse_args().record_procs
syscalls_logger = parser.parse_args().syscalls_logger
coverage = parser.parse_args().coverage
image_dir = parser.parse_args().image_dir
data_dir = parser.parse_args().data_dir
result_dir = parser.parse_args().result_dir

netargs = QEMU_NETWORK.split(" ")

# Create /tmp/[start|stop]_[IID].sh to start and stop network. If something goes wrong
# you may need to run /tmp/stop_[IID].sh to tear down the network

for (name, data) in [("start", START_NET), ("stop", STOP_NET)]:
    if len(data.strip()):
        with open(f"/tmp/{name}_{IID}.sh", "w") as f:
            f.write(data)

def network_setup(start = False, stop = False):
    if not os.path.exists("/dev/net/tun"):
        if stop:
            # Only print message once
            return

        print("\nWARNING: no /dev/net/tun present. You're likely in a docker container where" + \
                "you don't have permissions. As  such, your rehosting is: \n****running in NO-NETWORK mode****\n")
    
    if start and len(START_NET.strip()):
        try:
            subprocess.check_output(["/bin/bash", f"/tmp/start_{IID}.sh"])
        except subprocess.CalledProcessError:
            # Try to reset network, then retry
            network_setup(stop=True)
            subprocess.check_output(["/bin/bash", f"/tmp/start_{IID}.sh"])

    if stop and len(STOP_NET.strip()):
        subprocess.check_output(["/bin/bash", f"/tmp/stop_{IID}.sh"])

# Note armel is just panda-system-arm and mipseb is just panda-system-mips
configs = {"armel": {"qemu_machine": "virt",
                     "arch":         "arm",
                     "rootfs":       "/dev/vda1",
                     "kconf_group":  "armel",
                     "kernel":       bindir + "zImage.armel",
                     "drive":        f'file={image},format=raw,id=rootfs,if=none',
                     "extra_args":   ['-device', 'virtio-blk-device,drive=rootfs']},

           "mipsel": {"qemu_machine": "malta",
                     "arch":         "mipsel",
                     "rootfs":       "/dev/sda1",
                     "kconf_group":  "mipsel",
                     "kernel":       bindir + "vmlinux.mipsel.4",
                     "drive":        f'format=raw,file={image}',
                     "extra_args":   []},

           "mipseb": {"qemu_machine": "malta",
                     "arch":         "mips",
                     "rootfs":       "/dev/sda1",
                     "kconf_group":  "mipseb",
                     "kernel":       bindir + "vmlinux.mipseb.4",
                     "drive":        f'format=raw,file={image}',
                     "extra_args":   []},
          }

config = configs[ARCHEND]
### Now patch panda config with the FirmSolo configs

FIRMAE_KERNEL="true"

if ARCHEND == "armel":
    tty = "ttyS1"
else:
    tty = "ttyS0"

append = f"root={config['rootfs']} {QEMU_INIT} console={tty} nandsim.parts=64,64,64,64,64,64,64,64,64,64 \
          rw debug ignore_loglevel print-fatal-signals=1 \
          user_debug=31 mem=256M firmadyne.syscall=0 firmadyne.reboot=1 firmadyne.execute=1 firmadyne.procfs=1 firmadyne.devfs=1  FIRMAE_NET=true FIRMAE_NVRAM=true FIRMAE_KERNEL=true FIRMAE_ETC=true"

args = [ '-M',     config['qemu_machine'],
        '-kernel', config['kernel'],
        '-append', append,
        '-drive',  config['drive'],
        '-chardev', f'stdio,id=char0,logfile={scratch}/qemu.final.serial.log,signal=off',
        '-serial', 'chardev:char0',
        '-serial', f'unix:/tmp/qemu.{IID}.S1,server,nowait',
        '-nographic'] +  config['extra_args']

# Add the networking options
args.extend(netargs)

network_setup(stop=True)
network_setup(start=True)


kernel_conf = f"/Pandawan/kernel_profiles/vmlinux-{ARCHEND}.conf"

panda = Panda(config['arch'], mem="256", extra_args=args)
panda.set_os_name("linux-32-generic")
panda.load_plugin("syscalls2", args = {"load-info": True})
panda.load_plugin("osi", args = {"disable-autoload":True})
panda.load_plugin("osi_linux", args = {"kconf_file": kernel_conf,
                                        "kconf_group": config['kconf_group']})
if time_frame:
    panda.pyplugins.load(FwInitStopFinder, {'fw_name':f'{IID}', 'time_frame':f'{time_frame}', 'logfile': f'{scratch}/proc_logs.txt', 'global_logs' : f'{scratch}/fw_init_stop_pandawan.csv', "panda_pid": f"{os.getpid()}"})

# Set PANDA logging
panda.set_pandalog(scratch+"/results.plog")

# Add additional plugins in within the callback below
@panda.ppp("syscalls2", "on_all_sys_enter")
def first_syscall(cpu, pc, callno):
    panda.disable_ppp("first_syscall")
    print("Guest issued first syscall")
    if syscalls_logger:
        panda.load_plugin("syscalls_logger")
    if trace:
        panda.pyplugins.load(KmodFuncTracer, {'scratch':f'{scratch}'})
    if coverage:
        panda.load_plugin("coverage", {'mode': 'osi-block', 'summary': True, 'filename': f'{scratch}/coverage.csv', 'privilege' : 'user'})

try:
    panda.run()
except KeyboardInterrupt:
    panda.end_analysis()
    print("\nUser stopping for ctrl-c\n")

finally:
    print("Finishing...")
    panda.panda_finish()
    network_setup(stop=True)
