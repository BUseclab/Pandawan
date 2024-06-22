#!/bin/bash

set -e
set -u

# ${3} is Pandawan's dir
if [ -e ./pandawan.config ]; then
    source ./pandawan.config
elif [ -e ../pandawan.config ]; then
    source ../pandawan.config
elif [ -e ${3}/emul_config/pandawan.config ]; then
    source ${3}/emul_config/pandawan.config
else
    echo "Error: Could not find 'pandawan.config'!"
    exit 1
fi 

if check_number $1; then
    echo "Usage: run.armel.sh <image ID>"
    exit 1
fi
IID=${1}
QEMU_INIT=${2}

WORK_DIR=`get_scratch ${IID}`
IMAGE=`get_fs ${IID}`
KERNEL=`get_kernel "armelv6" ${IID}`
QEMU_MACHINE=`get_qemu_machine "armelv6"`
QEMU_ROOTFS=`get_qemu_disk "armelv6"`

if (${FIRMAE_NET}); then
  QEMU_NETWORK="-net nic -net socket,listen=:2001 -net nic -net socket,listen=:2002 -net nic -net socket,listen=:2003"
else
  QEMU_NETWORK="-net nic,vlan=0 -net socket,vlan=0,listen=:2000 -net nic,vlan=1 -net socket,vlan=1,listen=:2001 -net nic,vlan=2 -net socket,vlan=2,listen=:2002 -net nic,vlan=3 -net socket,vlan=3,listen=:2003"
fi

QEMU_AUDIO_DRV=none qemu-system-arm -m 256 -M ${QEMU_MACHINE} -kernel ${KERNEL} -cpu arm11mpcore -drive if=sd,file=${IMAGE},format=raw -append "mem=256M rootwait fdyne_syscall=1 root=${QEMU_ROOTFS} console=ttyAMA0 nandsim.parts=64,64,64,64,64,64,64,64,64,64 ${QEMU_INIT} rw debug ignore_loglevel print-fatal-signals=1 FIRMAE_NET=${FIRMAE_NET} FIRMAE_NVRAM=${FIRMAE_NVRAM} FIRMAE_KERNEL=${FIRMAE_KERNEL} FIRMAE_ETC=${FIRMAE_ETC} user_debug=31" -serial file:${WORK_DIR}/qemu.initial.serial.log -serial unix:/tmp/qemu.${IID}.S1,server,nowait -monitor unix:/tmp/qemu.${IID},server,nowait -display none ${QEMU_NETWORK}
