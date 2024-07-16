# Build a docker container for re-hosting with FirmSolo

# Build: docker build -t pandawan .
# Run: docker run -v $(pwd):/output --rm -it --privileged pandawan /bin/bash

FROM --platform=amd64 firmsolo_dev:latest

# Set the installation directory
ARG INSTALL_DIR=/opt

# Set environment variables
ENV DEBIAN_FRONTEND=noninteractive
ENV PIP_ROOT_USER_ACTION=ignore

# Install packages
RUN apt-get update && apt-get install -y \
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
	qemu-utils \
	curl \
	tar \
	bc \
	python3 \
	python3-pip \
	docker.io \
	libpq-dev \
	busybox-static \
	bash-static \
	fakeroot \
	dmsetup \
	kpartx \
	netcat-openbsd \
	nmap \
	python3-psycopg2 \
	snmp \
	uml-utilities \
	util-linux \
	vlan \
	mtd-utils \
	gzip \
	bzip2 \
	arj \
	lhasa \
	p7zip \
	p7zip-full \
	cabextract \
	fusecram \
	cramfsswap \
	squashfs-tools \
	sleuthkit \
	default-jdk \
	cpio \
	lzop \
	lzma \
	srecord \
	zlib1g-dev \
	liblzma-dev \
	liblzo2-dev \
	unzip \
	python3-magic \
	openjdk-8-jdk \
	unrar \
	git \
	wget \
	build-essential \
	sudo

# Upgrade pip and install Python packages
RUN python3 -m pip install --upgrade pip && \
		python3 -m pip install coloredlogs psycopg2 psycopg2-binary \
		python-lzo cstruct ubi_reader ply anytree sympy requests pexpect \
		scipy python-Levenshtein

# Install binwalk from FirmAE
RUN cd ${INSTALL_DIR} && \
		wget https://github.com/ReFirmLabs/binwalk/archive/refs/tags/v2.3.4.tar.gz && \
		tar -xf v2.3.4.tar.gz && \
		cd binwalk-2.3.4 && \
		sed -i 's/^install_ubireader//g;s/^install_sasquatch//g' deps.sh && \
		git clone --quiet --depth 1 --branch "master" https://github.com/devttys0/sasquatch && \
		cd sasquatch && \
		wget https://github.com/devttys0/sasquatch/pull/51.patch && patch -p1 <51.patch && \
		./build.sh && cd .. && \
		echo y | ./deps.sh && \
		python3 setup.py install

# Install custom FirmAE version
RUN cd ${INSTALL_DIR} && \
		wget -N --continue https://github.com/BUseclab/Pandawan/releases/download/v1.0.0/firmae.tar.gz && \
		tar xvf firmae.tar.gz && \
		rm firmae.tar.gz && \
		cd FirmAE && ./download.sh

# Install custom Firmadyne version
RUN cd ${INSTALL_DIR} && \
		wget -N --continue https://github.com/BUseclab/Pandawan/releases/download/v1.0.0/firmadyne.tar.gz && \
		tar xvf firmadyne.tar.gz && \
		rm firmadyne.tar.gz && \
		cd firmadyne && ./download.sh && \
		pg_ctlcluster 14 main start && \
		echo "firmadyne\nfirmadyne" | sudo -u postgres createuser -P firmadyne && \
		sudo -u postgres createdb -O firmadyne firmware && \
		sudo -u postgres psql -d firmware < ${INSTALL_DIR}/firmadyne/database/schema

# Install TriforceAFL
RUN git clone https://github.com/BUseclab/TriforceAFL.git ${INSTALL_DIR}/TriforceAFL && \
		cd ${INSTALL_DIR}/TriforceAFL && \
		make

# Install TriforceLinuxSyscallFuzzer
RUN git clone -b pandawan https://github.com/BUseclab/TriforceLinuxSyscallFuzzer.git ${INSTALL_DIR}/TriforceLinuxSyscallFuzzer && \
		cd ${INSTALL_DIR}/TriforceLinuxSyscallFuzzer/pandawan && \
		./compile_harnesses.sh
		
ADD panda_patches ${INSTALL_DIR}/Pandawan/panda_patches

# Install PANDA
RUN git clone --recursive https://github.com/panda-re/panda.git ${INSTALL_DIR}/panda && \
cd ${INSTALL_DIR}/panda && \
./panda/scripts/install_ubuntu.sh && \
make clean && \
git checkout ea682853034aeb5df110fec4e439420162d65c4f && \
git apply ${INSTALL_DIR}/Pandawan/panda_patches/0001-Changes-added-for-pandawan.patch && \
git apply ${INSTALL_DIR}/Pandawan/panda_patches/0003-A-fix-for-syscalls_logger.patch && \
git apply ${INSTALL_DIR}/Pandawan/panda_patches/0005-Patch-coverage-plugin-to-print-info-about-the-origin.patch

# Install rust
RUN cd ${INSTALL_DIR}/panda/build && curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs > rust.sh && \
chmod +x ./rust.sh && \
./rust.sh -y

ENV PATH="/root/.cargo/bin:${PATH}"

# Install rustup & Fixup Installation
RUN rustup toolchain install 1.66.1 && \
rustup default 1.66.1 && \
apt install execstack -y && \
execstack -c /root/.rustup/toolchains/1.66.1-x86_64-unknown-linux-gnu/lib/libLLVM-15-rust-1.66.1-stable.so && \
echo "deb [arch=amd64] http://archive.ubuntu.com/ubuntu focal main universe" >> /etc/apt/sources.list && \
apt update && \
apt install -y --allow-downgrades openssl=1.1.1f-1ubuntu2

# Build PANDA
RUN cd ${INSTALL_DIR}/panda/build && \
../build.sh --python

RUN mkdir -p ${INSTALL_DIR}/Pandawan/emul_config && \
cd ${INSTALL_DIR}/Pandawan/emul_config && \
wget -N --continue https://github.com/BUseclab/Pandawan/releases/download/v1.0.0/binaries.tar.gz && \
tar xvf binaries.tar.gz && \
rm binaries.tar.gz

# Install FirmSolo
RUN git clone --recursive -b pandawan https://github.com/BUseclab/FirmSolo.git ${INSTALL_DIR}/FirmSolo && \
		cd ${INSTALL_DIR}/FirmSolo && \
		git clone https://github.com/BUseclab/FirmSolo-data.git && \
		mv ./FirmSolo-data/buildroot_fs.tar.gz . && \
		rm -rf ./FirmSolo-data && \
		tar xvf buildroot_fs.tar.gz && \
		rm buildroot_fs.tar.gz

# Add unstuff binary
ADD emul_config/core/unstuff /usr/local/bin/

# Add your local Pandawan repository
# If you are doing development, comment this line and use a bind mount instead.
# ADD . ${INSTALL_DIR}/Pandawan

# Set working directory
ENV INSTALL_DIR=${INSTALL_DIR}
WORKDIR ${INSTALL_DIR}

ENTRYPOINT ["/bin/bash", "-l", "-c"]
