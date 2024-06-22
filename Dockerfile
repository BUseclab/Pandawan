# Build a docker container for re-hosting with FirmSolo

# Build: docker build -t pandawan .
# Run: docker run -v $(pwd):/output --rm -it --privileged pandawan /bin/bash

FROM firmsolo_dev:latest

# Install dependencies
ENV DEBIAN_FRONTEND=noninteractive
# Install Pandawan
RUN git clone https://github.com/BUseclab/Pandawan.git /Pandawan && \
	/Pandawan/install.sh /

ENTRYPOINT ["/bin/bash", "-l", "-c"]
