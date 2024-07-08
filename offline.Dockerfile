# A partial dockerfile for faster development

FROM --platform=amd64 pandawan_base:latest

# Add your local Pandawan repository
ADD . ${INSTALL_DIR}/Pandawan

	# Set working directory
ENV INSTALL_DIR=${INSTALL_DIR}
WORKDIR ${INSTALL_DIR}

ENTRYPOINT ["/bin/bash", "-l", "-c"]
