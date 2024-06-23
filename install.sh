#!/bin/bash

INSTALL_DIR=$1

export DEBIAN_FRONTEND=noninteractive
apt-get update && apt-get install -y \
	build-essential \
	zlib1g-dev \
	pkg-config \
	libglib2.0-dev \
	binutils-dev \
	libboost-all-dev \
	autoconf \
	libtool \
	libssl-dev \
	libpixman-1-dev \
	libpython3-dev \
	python3-pip \
	python3-capstone \
	python-is-python3 \
	virtualenv \
	sudo \
	gcc \
	make \
	g++ \
	python3 \
	python2 \
	flex \
	bison \
	dwarves \
	kmod \
	universal-ctags \
	kpartx \
	fdisk \
	fakeroot \
	git \
	dmsetup \
	rsync \
	netcat-openbsd \
	nmap \
	python3-psycopg2 \
	snmp \
	uml-utilities \
	util-linux \
	vlan \
	busybox-static \
	postgresql \
	wget \
	cscope \
	gcc-5-mips-linux-gnu \
	gcc-5-mipsel-linux-gnu \
	qemu \
	qemu-system-arm \
	qemu-system-mips \
	qemu-system-mipsel \
	qemu-utils

export PIP_ROOT_USER_ACTION=ignore

# These are FirmAE stuff
sudo apt install -y curl tar bc
sudo python3 -m pip install --upgrade pip
sudo python3 -m pip install coloredlogs

# for docker
sudo apt install -y docker.io
sudo groupadd docker
sudo usermod -aG docker $USER

sudo apt install -y libpq-dev
python3 -m pip install psycopg2 psycopg2-binary

sudo apt install -y busybox-static bash-static fakeroot dmsetup kpartx netcat-openbsd nmap python3-psycopg2 snmp uml-utilities util-linux vlan


cd ${INSTALL_DIR}/Pandawan/emul_config/

wget -N --continue https://github.com/BUseclab/Pandawan/releases/download/v1.0.0/binaries.tar.gz
tar xvf binaries.tar.gz && rm binaries.tar.gz

cd ${INSTALL_DIR}

# Install binwalk from FirmAE
wget https://github.com/ReFirmLabs/binwalk/archive/refs/tags/v2.3.4.tar.gz && \
  tar -xf v2.3.4.tar.gz && \
  cd binwalk-2.3.4 && \
  sed -i 's/^install_ubireader//g' deps.sh && \
  echo y | ./deps.sh && \
  sudo python3 setup.py install
sudo apt install -y mtd-utils gzip bzip2 tar arj lhasa p7zip p7zip-full cabextract fusecram cramfsswap squashfs-tools sleuthkit default-jdk cpio lzop lzma srecord zlib1g-dev liblzma-dev liblzo2-dev unzip

cd ${INSTALL_DIR}

sudo cp ${INSTALL_DIR}/Pandawan/emul_config/core/unstuff /usr/local/bin/

python3 -m pip install python-lzo cstruct ubi_reader
sudo apt install -y python3-magic openjdk-8-jdk unrar

# Back to FirmSolo stuff


# Install FirmSolo
git clone --recursive -b pandawan https://github.com/BUseclab/FirmSolo.git ${INSTALL_DIR}/FirmSolo && \
        cd /FirmSolo && \
        git clone https://github.com/BUseclab/FirmSolo-data.git && \
        mv ./FirmSolo-data/buildroot_fs.tar.gz . && rm -rf ./FirmSolo-data && \
        tar xvf buildroot_fs.tar.gz && rm buildroot_fs.tar.gz

cd ${INSTALL_DIR}

# Install custom FirmAE version
wget -N --continue https://github.com/BUseclab/Pandawan/releases/download/v1.0.0/firmae.tar.gz
tar xvf firmae.tar.gz
rm firmae.tar.gz
cd FirmAE/ && ./download.sh

cd ${INSTALL_DIR}

# Install custom Firmadyne version
wget -N --continue https://github.com/BUseclab/Pandawan/releases/download/v1.0.0/firmadyne.tar.gz
tar xvf firmadyne.tar.gz
rm firmadyne.tar.gz
cd firmadyne/ && ./download.sh

pip3 install ply anytree sympy requests pexpect scipy Levenshtein

git clone https://github.com/BUseclab/TriforceAFL.git ${INSTALL_DIR}/TriforceAFL && \
	cd /TriforceAFL && \
	make

cd ${INSTALL_DIR}

git clone -b pandawan https://github.com/BUseclab/TriforceLinuxSyscallFuzzer.git ${INSTALL_DIR}/TriforceLinuxSyscallFuzzer && \
	cd TriforceLinuxSyscallFuzzer/pandawan/ && \
	./compile_harnesses.sh

cd ${INSTALL_DIR}

#TODO: Dont run the install_ubuntu.sh script, just download all the packages needed
git clone --recursive https://github.com/panda-re/panda.git && \
	cd panda && \
	./panda/scripts/install_ubuntu.sh 

cd ${INSTALL_DIR}/panda && make clean && \
	git checkout ea682853034aeb5df110fec4e439420162d65c4f && \
	git apply ${INSTALL_DIR}/Pandawan/panda_patches/0001-Changes-added-for-pandawan.patch && \
	git apply ${INSTALL_DIR}/Pandawan/panda_patches/0003-A-fix-for-syscalls_logger.patch && \
	git apply ${INSTALL_DIR}/Pandawan/panda_patches/0005-Patch-coverage-plugin-to-print-info-about-the-origin.patch && \
	cd build && \
	curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs > rust.sh && \
	chmod +x ./rust.sh && \
	./rust.sh -y && source $HOME/.cargo/env && \
	rustup toolchain install 1.66.1 && rustup default 1.66.1 && \
	../build.sh --python

# Set the symlinks for mips gcc-5
ln -s /bin/mips-linux-gnu-gcc-5 /bin/mips-linux-gnu-gcc && \
	ln -s /bin/mipsel-linux-gnu-gcc-5 /bin/mipsel-linux-gnu-gcc

