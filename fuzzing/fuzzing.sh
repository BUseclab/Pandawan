#!/bin/bash

echo core >/proc/sys/kernel/core_pattern
cd /sys/devices/system/cpu
echo performance | tee cpu*/cpufreq/scaling_governor

PANDAWAN_DIR=${1}

cd /output
${1}/data_gathering/get_kernel_traces.py ${2}
if sudo ${1}/fuzzing/triforce_run.py -i ${2} -t "${3}m" ; then
    echo "done with "${2}
fi
cd /