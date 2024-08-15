# Pandawan

Pandawan is a Linux-based firmware re-hosting framework that holistically (both the user and kernel level) re-hosts and analyzes IoT firmware.
Specifically, Pandawan builds ``augmented'' custom kernels supported by QEMU that are conducive to holistc re-hosting and analysis.
Pandawan uses as its foundation the FirmSolo, FirmAE and (Py)PANDA frameworks.
Finally, Pandawan enables the comparison of different Linux-based firmware re-hosting frameworks (e.g., Pandawan, FirmSolo, Firmadyne, and FirmAE) across their re-hosting capabilities.
Currently, we use the executed user programs, the unique executed user QEMU TBs, the kernel modules loaded and unique kernel module TBs executed as our comparison metrics.

This repository contains the prototype implementation of Pandawan based on the Usenix 2024 [paper](https://github.com/BUseclab/Pandawan/blob/main/paper/paper.pdf)

**Note:** Some parts of the code may need cleanup or re-writing in the worst case, thus this prototype is not yet ready for production.

# Docker
Below there is a link to a base docker image that can be used along with the Dockerfile to build the FirmSolo docker. We highly recommend you use that since all the artifacts (e.g., Pandawan's and the other compared systems' source code, etc) will be setup within the docker (We shared the same image as FirmSolo).

You can find the docker image here:
https://doi.org/10.5281/zenodo.7865451

Execute:

```
docker load < firmsolo.tar.gz

cd <pw_install_dir>/

docker build -t pandawan .
```

Change `<pw_install_dir>` to the directory where you cloned Pandawan.

**Running the docker**

```
mkdir -p workdir

cd workdir

docker run -v $(pwd):/output --rm -it --privileged pandawan /bin/bash
```

It is assumed that your work directory (`<work_dir>`) is the current directory (`$(pwd)`)

Inside the docker run:
```
mkdir -p /output/images/
echo core >/proc/sys/kernel/core_pattern
cd /sys/devices/system/cpu
echo performance | tee cpu*/cpufreq/scaling_governor
```


**Note:** The container needs to be privileged since some operations require root permissions, such as creating/mounting file-systems.

Since all the Pandawan artifacts are installed in the docker, you can skip to the Examples sections.

# Manual Installation
If you want to install Pandawan manually you first need to install some dependencies (We recommend using the Docker image). Execute the `install.sh` script:

```
bash <pw_install_dir>/Pandawan/install.sh <pw_install_dir>
```
**Note:** We are using qemu-2.12 since it is compatible with FirmSolo and Firmadyne. If you want to use this version of QEMU then you need to install it manually. Follow the instructions here: https://www.qemu.org/download/. Furthermore the `install.sh` script will use unavailable legacy toolchains to compile specific binaries that will be used (e.g., the fuzzing harnesses). We recommend using the docker image since it has the necessary toolchains already installed. In the future we will update our scripts to also use newer toolchains. Finally, Pandawan was tested with an older PANDA version (commit:ea682853034aeb5df110fec4e439420162d65c4f). We will update the PANDA version in the future.

**Install Ghidra:**

Follow instuctions in https://ghidra-sre.org/InstallationGuide.html

**Toolchains**

Please refer to https://github.com/BUseclab/FirmSolo.git on how to setup the toolchains that will be used to compile the custom kernels (set the toolchains within FirmSolo's installation directory).

# Instructions
The main interface to Pandawan is the `run_pandawan.py` script in the root directory:

```
usage: run_pandawan.py [-h] [-g GLOBAL_TIMEOUT] [-s] [-a] [-t [STEPS ...]] [-f] [-e] [-d] [-p PLUGIN_OPTS] [-c] image

Run Pandawan

positional arguments:
  image                 Either the path to the firmware image or the ID of an extracted firmware image

options:
  -h, --help            show this help message and exit
  -g GLOBAL_TIMEOUT, --global_timeout GLOBAL_TIMEOUT
                        Global timeout in seconds for the pandawan emulation
  -s, --do_subs         Do the pandawan substitutions
  -a, --all             Run all the analysis steps
  -t [STEPS ...], --steps [STEPS ...]
                        Which of the analysis steps to run? ([s1, s2a, s2b, s2c, oracle, script_config, emul])
  -f, --firmsolo        Compile the stock FirmSolo kernels without Pandawans augmentation
  -e, --firmae_stock    Run FirmAE stock
  -d, --firmadyne_stock
                        Run Firmadyne stock
  -p PLUGIN_OPTS, --plugin_opts PLUGIN_OPTS
                        The pypanda plugins to enable. Provided as "\-f 300 \-s \-t \-c" (f:ficd, s:syscalls_logger, t:syscalltokmodtracer, c:coverage)
  -c, --comparison      Print the comparison metrics (User programs, User coverage (BBs), KOs loaded, KO coverage (BBs))
```
**Note:** Pandawan takes as input either a firmware image blob and will create an image ID for it, or the ID of an already extracted firmware image (The image's .tar.gz must be present in the `<work_dir>`/images/ directory).

**Configuration (No need to run if the docker is used)**

First edit the `paths.py` script and specify these paths:
```
pandawan_dir
firmsolo_dir
firmae_dir
firmadyne_dir
output_dir
```

Also follow the guidelines in https://github.com/BUseclab/FirmSolo.git on how to setup FirmSolo's `custom_util.py` script.
If you want to use our compatible with Pandawan versions of FirmAE and Firmadyne you have to change the necessary paths in `firmae.config` and `firmadyne.config` files, respectively as instructed in https://github.com/pr0v3rbs/FirmAE and https://github.com/firmadyne/firmadyne. If you are using the Docker image all these paths are already set for you.

Run:
```
mkdir -p <work_dir>/images/
```

The `images` directory stores the extracted file-systems and kernels of the target firmware images.

**Re-hosting**

To run the re-hosting experiments of Pandawan execute:

```
run_pandawan.py 14092 -a -s -d -g 2700 -p "\-f 300 \-s \-c \-t"
```

The above command will run all the steps of Pandawan's re-hosting process while enabling all the PyPANDA plugins (`-p` takes the arguments that will be given to the dedicated PyPANDA scripts created for each image). Specifically, the `-f 300` option enables the FICD plugin with a time-frame of 300 seconds and `\-t` enables the `SyscallToKmodTracer` plugin. The `-s` enables PANDA's `syscalls_logger` plugin and `-c` enables PANDA's `coverage` plugin.

To run the re-hosting experiments for FirmSolo, Firmadyne, and FirmAE execute these commands:

```
python3 run_pandawan.py <image_id> -a -f -s -g 2700 -p "\-f 300 \-s \-c \-t"

python3 run_pandawan.py <image_id> -a -d -s -g 2700 -p "\-f 300 \-s \-c \-t"

python3 run_pandawan.py <image_id> -a -e -s -g 2700 -p "\-f 300 \-s \-c \-t"
```

These might take a while.

**Comparison**

To extract the comparison metrics for an image (for all compared re-hosting systems) execute:

```
python3 run_pandawan.py <image_id> -c
```

# Fuzzing

To initiate the fuzzing of a firmware image's kernel modules with TriforceAFL execute:

```
./fuzzing/fuzzing.sh <pw_install_dir> <image_id> <minutes_to_fuzz>
```

where `<pw_install_dir>` is the absolute path to the install directory of Pandawan (`/` in the Docker image) and `<minutes_to_fuzz>` is the number of minutes to fuzz

The script will first create seeds for TriforceAFL based on the traced syscalls (ID and arguments) that lead to the execution of the code of kernel modules in the target image.
Next, the script will invoke TriforceAFL to fuzz the kernel modules using these seeds.

#TODO:
Add a crash reproducer.

# Examples

To get the example images, on your host execute :

```
git clone https://github.com/BUseclab/FirmSolo-data.git

mv ./FirmSolo-data/images/ <work_dir>
```

You should change the `<work_dir>` to your work directory on your host machine (if you are using Docker this directory should correspond to the `/output/` directory in the container).

**To analyze example 1 execute:**
```
python3 <pw_install_dir>/run_pandawan.py 1 -a -s -g 2700 -p "\-f 300 \-s \-c \-t"

python3 <pw_install_dir>/run_pandawan.py 1 -a -f -s -g 2700 -p "\-f 300 \-s \-c \-t"

python3 <pw_install_dir>/run_pandawan.py 1 -a -d -s -g 2700 -p "\-f 300 \-s \-c \-t"

python3 <pw_install_dir>/run_pandawan.py 1 -a -e -s -g 2700 -p "\-f 300 \-s \-c \-t"

python3 <pw_install_dir>/run_pandawan.py 1 -c

```

Change `<pw_install_dir>` to the installation directory of Pandawan (`/Pandawan` if you are working within the docker).

Please excuse the ugly prints during the analysis. If everything worked correctly you should be getting:

```
Metrics for image 1 across the compared re-hosting systems
System: pandawan
        Executed programs: 23, Unique BBs: 11463
        Total KOs: 75, Loaded KOs: 35, Persistent crashes: 0
        Unique KO TBs: 881
System: firmsolo
        Executed programs: 23, Unique BBs: 11510
        Total KOs: 75, Loaded KOs: 35, Persistent crashes: 0
        Unique KO TBs: 787
System: firmae
        Executed programs: 23, Unique BBs: 11862
        System firmae does not load KOs
        System firmae does not execute KO code
System: firmadyne
        Executed programs: 23, Unique BBs: 11209
        System firmadyne does not load KOs
        System firmadyne does not execute KO code
```

**Note:** The resulting number might differ slightly.

**To run TriforceAFL for 30 minutes:**

```
<pw_install_dir>/fuzzing/fuzzing.sh <pw_install_dir> 1 30
```

This will fuzz the kernel modules within image 1 that have at least one valid seed (chains of syscalls that lead to the execution of these modules).
You will find the fuzzers output within: `<work_dir>/Fuzz_Results_Curr/1/`. We will include a crash reproducer in the future to quickly check the bugs found by the fuzzer.

**Note:** To run example 2 just replace the image id in the above commands with 2.

**Analyze custom firmware images:**

To analyze firmware images besides our examples, you first need to extract their file-system and kernel.
Then you can provide the path to the firmware image blob to Pandawan instead of an image ID to analyze the image. Once you run the experiments once you can continue using the ID that is created by Pandawan afterwards. 

# Bibtex citation

```
@inproceedings {pandawan,
author = {Ioannis Angelakopoulos, Gianluca Stringhini and Manuel Egele},
title = {Pandawan: Quantifying Progress in Linux-based Firmware Rehosting},
booktitle = {{USENIX} Security Symposium},
year = {2024},
publisher = {{USENIX} Association},
month = aug,
}
```
# Contact us
For any further information contact `jaggel@bu.edu`.
