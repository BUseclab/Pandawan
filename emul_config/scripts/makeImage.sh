#!/bin/bash

#set -e
set -u

PANDAWAN_DIR=${3}
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
    echo "Usage: makeImage.sh <image ID> [<architecture>]"
    exit 1
fi

if check_root; then
    echo "Error: This script requires root privileges!"
    exit 1
fi

USER=$(whoami)

IID=${1}
ARCH=${2}

echo "----Running----"
WORK_DIR=`get_scratch ${IID}`
IMAGE=`get_fs ${IID}`
IMAGE_DIR=`get_fs_mount ${IID}`

echo "----Copying Filesystem Tarball----"
mkdir -p "${WORK_DIR}"
chmod a+rwx "${WORK_DIR}"
chown -R "${USER}" "${WORK_DIR}"
chgrp -R "${USER}" "${WORK_DIR}"

if [ ! -e "${WORK_DIR}/${IID}.tar.gz" ]; then
    if [ ! -e "${TARBALL_DIR}/${IID}.tar.gz" ]; then
        echo "Error: Cannot find tarball of root filesystem for ${IID}!"
        exit 1
    else
        cp "${TARBALL_DIR}/${IID}.tar.gz" "${WORK_DIR}/${IID}.tar.gz"
    fi
fi

echo "----Creating QEMU Image----"
qemu-img create -f raw "${IMAGE}" 2G
chmod a+rw "${IMAGE}"

echo "----Creating Partition Table----"
echo -e "o\nn\np\n1\n\n\nw" | /sbin/fdisk -c=dos "${IMAGE}"

echo "----Mounting QEMU Image----"
#DEVICE=`add_partition ${IMAGE}`
DEVICE=$(get_device "$(kpartx -a -s -v "${IMAGE}")")
sleep 1

echo "----Creating Filesystem----"
sync
mkfs.ext2 "${DEVICE}"

echo "----Making QEMU Image Mountpoint----"
if [ ! -e "${IMAGE_DIR}" ]; then
    mkdir "${IMAGE_DIR}"
    chown "${USER}" "${IMAGE_DIR}"
fi

echo "----Mounting QEMU Image Partition----"
sync
mount "${DEVICE}" "${IMAGE_DIR}"

echo "----Extracting Filesystem Tarball----"
tar -xvf "${WORK_DIR}/$IID.tar.gz" -C "${IMAGE_DIR}"
rm "${WORK_DIR}/${IID}.tar.gz"

echo "----Creating FIRMADYNE Directories----"
mkdir "${IMAGE_DIR}/firmadyne/"
mkdir "${IMAGE_DIR}/firmadyne/libnvram/"
mkdir "${IMAGE_DIR}/firmadyne/libnvram.override/"

cp $(which busybox) "${IMAGE_DIR}"
cp $(which bash-static) "${IMAGE_DIR}"
echo "----Finding Init (chroot)----"
if [ -e "${WORK_DIR}/kernelInit" ]; then
  cp "${WORK_DIR}/kernelInit" "${IMAGE_DIR}"
fi
cp "${SCRIPT_DIR}/inferFile.sh" "${IMAGE_DIR}"
FIRMAE_BOOT=${FIRMAE_BOOT} FIRMAE_ETC=${FIRMAE_ETC} chroot "${IMAGE_DIR}" /bash-static /inferFile.sh
rm "${IMAGE_DIR}/bash-static"
rm "${IMAGE_DIR}/inferFile.sh"
if [ -e "${IMAGE_DIR}/kernelInit" ]; then
  rm "${IMAGE_DIR}/kernelInit"
fi

mv ${IMAGE_DIR}/firmadyne/init ${WORK_DIR}
if [ -e ${IMAGE_DIR}/firmadyne/service ]; then
  cp ${IMAGE_DIR}/firmadyne/service ${WORK_DIR}
fi

echo "----Patching Filesystem (chroot)----"
cp "${SCRIPT_DIR}/fixImage.sh" "${IMAGE_DIR}"
FIRMAE_BOOT=${FIRMAE_BOOT} FIRMAE_ETC=${FIRMAE_ETC} chroot "${IMAGE_DIR}" /busybox ash /fixImage.sh
rm "${IMAGE_DIR}/fixImage.sh"
rm "${IMAGE_DIR}/busybox"

echo "----Finding the FirmSolo upstream module directory----"
KERN=`find ${FS_OUT_DIR}/results/${IID} -name linux-* -type d`

for BINARY_NAME in "${BINARIES[@]}"
do
    BINARY_PATH=`get_binary ${BINARY_NAME} ${ARCH}`
    cp "${BINARY_PATH}" "${IMAGE_DIR}/firmadyne/${BINARY_NAME}"
    chmod a+x "${IMAGE_DIR}/firmadyne/${BINARY_NAME}"
done

mkdir -p "${IMAGE_DIR}/fuzzing"
mkdir -p "${IMAGE_DIR}/bin/"

echo "----Setting up FIRMADYNE----"
${SCRIPT_DIR}/copy_binaries.py ${FIRMAE_DIR} ${KERN} ${ARCH} ${IMAGE_DIR} ${WORK_DIR} ${FS_SCRIPT_DIR}

if [[ ${ARCH} == mips* ]];
then
	mknod -m 666 "${IMAGE_DIR}/firmadyne/ttyS1" c 4 65
else
	mknod -m 666 "${IMAGE_DIR}/firmadyne/ttyS1" c 204 65
fi

cp "${SCRIPT_DIR}/preInit.sh" "${IMAGE_DIR}/firmadyne/preInit.sh"
chmod a+x "${IMAGE_DIR}/firmadyne/preInit.sh"

cp "${SCRIPT_DIR}/network.sh" "${IMAGE_DIR}/firmadyne/network.sh"
chmod a+x "${IMAGE_DIR}/firmadyne/network.sh"

cp "${SCRIPT_DIR}/run_service.sh" "${IMAGE_DIR}/firmadyne/run_service.sh"
chmod a+x "${IMAGE_DIR}/firmadyne/run_service.sh"

cp "${SCRIPT_DIR}/injectionChecker.sh" "${IMAGE_DIR}/bin/a"
chmod a+x "${IMAGE_DIR}/bin/a"

touch "${IMAGE_DIR}/firmadyne/debug.sh"
chmod a+x "${IMAGE_DIR}/firmadyne/debug.sh"

echo "----Creating upstream module directory----"
mkdir "${IMAGE_DIR}/upstream"

echo "----Copying the native modules to the filesystem----"
cp -r ${KERN}/lib/modules/* ${IMAGE_DIR}/upstream/
ls -l ${IMAGE_DIR}/upstream/

echo "------Erasing Bad Modules------"
${SCRIPT_DIR}/erase_bad_modules.py ${IID} ${IMAGE_DIR} "no" ${FS_SCRIPT_DIR} ${PANDAWAN_DIR}


if (! ${FIRMAE_ETC}); then
  sed -i 's/sleep 60/sleep 15/g' "${IMAGE_DIR}/firmadyne/network.sh"
  sed -i 's/sleep 120/sleep 30/g' "${IMAGE_DIR}/firmadyne/run_service.sh"
  sed -i 's@/firmadyne/sh@/bin/sh@g' ${IMAGE_DIR}/firmadyne/{preInit.sh,network.sh,run_service.sh}
  sed -i 's@BUSYBOX=/firmadyne/busybox@BUSYBOX=@g' ${IMAGE_DIR}/firmadyne/{preInit.sh,network.sh,run_service.sh}
fi

echo "----Unmounting QEMU Image----"
sync
umount "${IMAGE_DIR}"
del_partition ${DEVICE} ${IMAGE}
