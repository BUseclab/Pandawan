# Build a docker container for re-hosting with FirmSolo

# Build: docker build -t pandawan .
# Run: docker run -v $(pwd):/output --rm -it --privileged pandawan /bin/bash

FROM firmsolo_dev:latest

# Install dependencies
ENV DEBIAN_FRONTEND=noninteractive
# Install Pandawan
RUN git clone https://github.com/BUseclab/Pandawan.git /Pandawan && \
	/Pandawan/install.sh / 2>&1 > /docker_build.log || echo "Something failed...Check /docker_build.log"

ENTRYPOINT ["/bin/bash", "-l", "-c"]
