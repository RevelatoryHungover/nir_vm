# Use a base image with Python 3.8 installed
FROM python:3.8

# Set environment variables
ENV LANG C.UTF-8
ENV LC_ALL C.UTF-8

# Install system dependencies
RUN apt-get update && apt-get install -y \
    graphviz \
 && rm -rf /var/lib/apt/lists/*

# Install Python dependencies
RUN pip install pyparsing==2.4.6 future==0.18.2

# Create a directory to store your local folder and copy it into the Docker image
RUN mkdir -p /usr/src/app/miasm
COPY miasm /usr/src/app/miasm
COPY nir_files /usr/src/app/nir_filess
# Set working directory
WORKDIR /usr/src/app

# Install the local Python package 'miasm'
RUN pip install ./miasm
COPY nir /usr/local/lib/python3.8/site-packages/miasm/arch/nir
COPY machine.py /usr/local/lib/python3.8/site-packages/miasm/analysis/machine.py


# Start a bash shell when the container is run
CMD ["/bin/bash"]

