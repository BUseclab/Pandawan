#!/bin/bash

function print_usage()
{
    echo "Usage: ${0} [mode]... [brand] [firmware|firmware_directory]"
    echo "mode: use one option at once"
    echo "      -r, --run     : run mode         - run emulation (no quit)"
    echo "      -c, --check   : check mode       - check network reachable and web access (quit)"
    echo "      -a, --analyze : analyze mode     - analyze vulnerability (quit)"
    echo "      -d, --debug   : debug mode       - debugging emulation (no quit)"
    echo "      -b, --boot    : boot debug mode  - kernel boot debugging using QEMU (no quit)"
}

if [ $# -ne 4 ]; then
    print_usage ${0}
    exit 1
fi

set -e
set -u

USER=$(whoami)
PANDAWAN_DIR="${4}"

if [ -e ./pandawan.config ]; then
    source ./pandawan.config
elif [ -e ../pandawan.config ]; then
    source ../pandawan.config
elif [ -e ${PANDAWAN_DIR}/emul_config/pandawan.config ]; then
    source ${PANDAWAN_DIR}/emul_config/pandawan.config
else
    echo "Error: Could not find 'pandawan.config'!"
    exit 1
fi 

if [ ! -d ${SCRATCH_DIR} ]; then
  mkdir -p ${SCRATCH_DIR};
fi

function get_option()
{
    OPTION=${1}
    if [ ${OPTION} = "-c" ] || [ ${OPTION} = "--check" ]; then
        echo "check"
    elif [ ${OPTION} = "-e" ] || [ ${OPTION} = "--extract" ]; then
        echo "extract"
    else
        echo "none"
    fi
}

function get_brand()
{
  INFILE=${1}
  BRAND=${2}
  if [ ${BRAND} = "auto" ]; then
    echo `./scripts/util.py get_brand ${INFILE} ${PSQL_IP}`
  else
    echo ${2}
  fi
}

OPTION=`get_option ${1}`
if [ ${OPTION} == "none" ]; then
  print_usage ${0}
  exit 1
fi

if (! id | egrep -sqi "root"); then
  echo -e "[\033[31m-\033[0m] This script must run with 'root' privilege"
  exit 1
fi

IID=${3}
WORK_DIR=""

echo "[*] ${2} FirmAE start!!!"
INFILE=${2}
PING_RESULT=false
WEB_RESULT=false
IP=''


# ================================
# extract filesystem from firmware
# ================================
t_start="$(date -u +%s.%N)"

WORK_DIR=`get_scratch ${IID}`
mkdir -p ${WORK_DIR}
chmod a+rwx "${WORK_DIR}"
chown -R "${USER}" "${WORK_DIR}"
chgrp -R "${USER}" "${WORK_DIR}"

if [ ${OPTION} == "extract" ]; then
    FILENAME=`basename ${INFILE%.*}`
    echo $FILENAME > ${WORK_DIR}/name
    python3 ${PANDAWAN_DIR}/sources/extractor/extractor.py -np -nk "$FILENAME" /tmp/${IID} | tee /tmp/log.txt
    mv /tmp/${IID}/*.tar.gz ${TARBALL_DIR}/${IID}.tar.gz

    # ================================
    # extract kernel from firmware
    # ================================
    
    sync

    if [ -e ${WORK_DIR}/result ]; then
        if (egrep -sqi "true" ${WORK_DIR}/result); then
            RESULT=`cat ${WORK_DIR}/result`
            return
        fi
        rm ${WORK_DIR}/result
    fi

    if [ ! -e ${TARBALL_DIR}/images/$IID.tar.gz ]; then
        echo -e "[\033[31m-\033[0m] The root filesystem is not!"
        echo "extraction fail" > ${WORK_DIR}/result
        return
    fi

    echo "[*] extract done!!!"
    t_end="$(date -u +%s.%N)"
    time_extract="$(bc <<<"$t_end-$t_start")"
    echo $time_extract > ${WORK_DIR}/time_extract
    return
fi
# ================================
# check architecture
# ================================
t_start="$(date -u +%s.%N)"
ARCH=`${SCRIPT_DIR}/getArch.py ${TARBALL_DIR}/$IID.tar.gz ${FS_SCRIPT_DIR} ${FS_OUT_DIR}`
echo "${ARCH}" > "${WORK_DIR}/architecture"

if [ -e ./images/${IID}.kernel ]; then
    ${SCRIPT_DIR}/inferKernel.py ${IID} ${SCRATCH_DIR} ${TARBALL_DIR}
fi

if [ ! "${ARCH}" ]; then
    echo -e "[\033[31m-\033[0m] Get architecture failed!"
    echo "get architecture fail" > ${WORK_DIR}/result
    return
fi
if ( check_arch ${ARCH} == 0 ); then
    echo -e "[\033[31m-\033[0m] Unknown architecture! - ${ARCH}"
    echo "not valid architecture : ${ARCH}" > ${WORK_DIR}/result
    return
fi

echo "[*] get architecture done!!!"
t_end="$(date -u +%s.%N)"
time_arch="$(bc <<<"$t_end-$t_start")"
echo $time_arch > ${WORK_DIR}/time_arch

if (! egrep -sqi "true" ${WORK_DIR}/web); then
    # ================================
    # make qemu image
    # ================================

    t_start="$(date -u +%s.%N)"
    ${SCRIPT_DIR}/makeImage.sh $IID $ARCH $PANDAWAN_DIR\
        2>&1 > ${WORK_DIR}/makeImage.log
    t_end="$(date -u +%s.%N)"
    time_image="$(bc <<<"$t_end-$t_start")"
    echo $time_image > ${WORK_DIR}/time_image

    # ================================
    # infer network interface
    # ================================
    t_start="$(date -u +%s.%N)"
    echo "[*] infer network start!!!"
    # TIMEOUT is set in "firmae.config". This TIMEOUT is used for initial
    # log collection.
    TIMEOUT=$TIMEOUT FIRMAE_NET=${FIRMAE_NET} \
        ${SCRIPT_DIR}/makeNetwork.py -i $IID -q -o -s ${FS_OUT_DIR} -r ${FS_SCRIPT_DIR} -p ${PANDAWAN_DIR}\
        &> ${WORK_DIR}/makeNetwork.log

    t_end="$(date -u +%s.%N)"
    time_network="$(bc <<<"$t_end-$t_start")"
    echo $time_network > ${WORK_DIR}/time_network
else
    echo "[*] ${INFILE} already succeed emulation!!!"
fi

if (egrep -sqi "true" ${WORK_DIR}/ping); then
    PING_RESULT=true
    IP=`cat ${WORK_DIR}/ip`
fi
if (egrep -sqi "true" ${WORK_DIR}/web); then
    WEB_RESULT=true
fi

echo -e "\n[IID] ${IID}\n[\033[33mMODE\033[0m] ${OPTION}"
if ($PING_RESULT); then
    echo -e "[\033[32m+\033[0m] Network reachable on ${IP}!"
fi
if ($WEB_RESULT); then
    echo -e "[\033[32m+\033[0m] Web service on ${IP}"
    echo true > ${WORK_DIR}/result
else
    echo false > ${WORK_DIR}/result
fi
