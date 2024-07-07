# A partial dockerfile for faster development

FROM --platform=amd64 pandawan_base:latest

# Add your local Pandawan repository
ADD . ${INSTALL_DIR}/Pandawan

# Download and extract Pandawan binaries to correct locations
RUN mkdir -p ${INSTALL_DIR}/Pandawan/emul_config && \
cd ${INSTALL_DIR}/Pandawan/emul_config && \
mv ${INSTALL_DIR}/binaries.tar.gz . && \
tar xvf binaries.tar.gz && \
rm binaries.tar.gz && \
cp ${INSTALL_DIR}/Pandawan/emul_config/core/unstuff /usr/local/bin/
	
	# Set working directory
ENV INSTALL_DIR=${INSTALL_DIR}
WORKDIR ${INSTALL_DIR}

ENTRYPOINT ["/bin/bash", "-l", "-c"]
