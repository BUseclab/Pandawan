#!/usr/bin/env python3
import os
import sys
import subprocess
from pandare import Panda
import pickle


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
parser.add_argument('-r','--record_procs', type=int, help='Enable the Record Procs plugin')

trace = parser.parse_args().kmod_trace
time_frame = parser.parse_args().time_frame
syscalls_logger = parser.parse_args().syscalls_logger
coverage = parser.parse_args().coverage
image_dir = parser.parse_args().image_dir
data_dir = parser.parse_args().data_dir
result_dir = parser.parse_args().result_dir
record_procs = parser.parse_args().record_procs

device_toggle = {"acos_nat_cli": 1, "brcmboard": 2, "dsl_cpe_api": 4, "gpio": 8, "nvram": 16,
                 "pib": 32, "sc_led": 64, "tca0": 128, "ticfg": 256, "watchdog": 512, "wdt" : 1024,
                 "zybtnio": 2048}
enable_device = 4095

netargs = QEMU_NETWORK.split(" ")
scratch = f"{result_dir}/{IID}/"
image = f"{image_dir}/{IID}/image.raw"
fs_data_file = f"{data_dir}/Loaded_Modules/{IID}/{IID}_ups_subs.pkl"
image_info = f"{data_dir}/Image_Info/{IID}.pkl"

def read_fs_mod_data():
    with open(fs_data_file, "rb") as f:
        temp = pickle.load(f)
    
    return temp[0], temp[-1]

def read_fs_image_data():
    with open(image_info, "rb") as f:
        res = pickle.load(f)

    return res
fs_image_info = read_fs_image_data()
kernel = f"{data_dir}/results/{IID}/linux-{fs_image_info['kernel']}/"
kernel_conf = f"{data_dir}/Loaded_Modules/{IID}/kernel-{fs_image_info['kernel']}.conf"


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
                     "rootfs":       "/dev/vda",
                     "kconf_group":  f"{IID}",
                     "kernel":       kernel + "zImage",
                     "drive":        f'file={image},format=raw',
                     "extra_args":   []},

           "mipsel": {"qemu_machine": "malta",
                     "arch":         "mipsel",
                     "rootfs":       "/dev/sda",
                     "kconf_group":  f"{IID}",
                     "kernel":       kernel + "vmlinux",
                     "drive":        f'format=raw,file={image}',
                     "extra_args":   []},

           "mipseb": {"qemu_machine": "malta",
                     "arch":         "mips",
                     "rootfs":       "/dev/sda",
                     "kconf_group":  f"{IID}",
                     "kernel":       kernel + "vmlinux",
                     "drive":        f'format=raw,file={image}',
                     "extra_args":   []},
          }

config = configs[ARCHEND]
### Now patch panda config with the FirmSolo configs
loaded_modules, qemu_opts = read_fs_mod_data()

FIRMAE_KERNEL="true"

for module in loaded_modules:
    if "acos_nat" in module:
        enable_device &= 4094
        FIRMAE_KERNEL="false"
    if "gpio" in module:
        enable_device &= 4087

config['qemu_machine'] = qemu_opts['machine']
config['cpu'] = qemu_opts['cpu']
if qemu_opts['iface'] != "":
    if qemu_opts['id'] != "" and qemu_opts['id'] != None:
        config['drive'] = "{}{}{}".format(qemu_opts['iface'], qemu_opts['id'], config['drive'])
    else:
        config['drive'] = "{}{}".format(qemu_opts['iface'], config['drive'])

else:
    config['drive'] = "{},{}".format('if=ide',config['drive'])

if qemu_opts['blk_dev'] == "/dev/hda":
    config['rootfs'] = "/dev/hda1"
elif qemu_opts['blk_dev'] == "/dev/sda":
    config['rootfs'] = "/dev/sda1"
elif qemu_opts['blk_dev'] == "/dev/vda":
    config['rootfs'] = "/dev/vda1"
else:
    config['rootfs'] = "/dev/mmcblk0p1"

append = f"root={config['rootfs']} {QEMU_INIT} console={qemu_opts['tty']} nandsim.parts=64,64,64,64,64,64,64,64,64,64 \
          rw rootwait debug ignore_loglevel print-fatal-signals=1 \
          user_debug=31 enable_device={enable_device} fdyne_reboot=1 fdyne_execute=1 firmadyne.procfs=1 firmadyne.devfs=1 mem=256M FIRMAE_NET=true FIRMAE_NVRAM=true FIRMAE_KERNEL={FIRMAE_KERNEL} FIRMAE_ETC=false"

if config['cpu'] != "":
    args = [ '-M',     config['qemu_machine'],
            '-kernel', config['kernel'],
            '-append', append,
            '-drive',  config['drive'],
            '-chardev', f'stdio,id=char0,logfile={scratch}/qemu.final.serial.log,signal=off',
            '-serial', 'chardev:char0',
            '-serial', f'unix:/tmp/qemu.{IID}.S1,server,nowait',
            '-cpu', config['cpu'].split()[1],
            '-nographic'] +  config['extra_args']
else:
    if qemu_opts['device'] != "":
        args = [ '-M',     config['qemu_machine'],
                '-kernel', config['kernel'],
                '-append', append,
                '-serial', f'unix:/tmp/qemu.{IID}.S1,server,nowait',
                '-chardev', f'stdio,id=char0,logfile={scratch}/qemu.final.serial.log,signal=off',
                '-serial', 'chardev:char0',
                '-drive',  config['drive'],
                '-device', qemu_opts['device'].split()[1],
                '-nographic'] + config['extra_args']
    else:
        args = [ '-M',     config['qemu_machine'],
                '-kernel', config['kernel'],
                '-append', append,
                '-chardev', f'stdio,id=char0,logfile={scratch}/qemu.final.serial.log,signal=off',
                '-serial', 'chardev:char0',
                '-serial', f'unix:/tmp/qemu.{IID}.S1,server,nowait',
                '-drive',  config['drive'],
                '-nographic'] + config['extra_args']


# Add the networking options
if ARCHEND == "armel" and fs_image_info['kernel'] < "4.0":
    pass
else:
    args.extend(netargs)

network_setup(stop=True)
network_setup(start=True)

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
