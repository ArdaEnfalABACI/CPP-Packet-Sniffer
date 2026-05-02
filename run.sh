#!/bin/bash

# Default values
OUTPUT_FILE="capture"
FILTER=""

# Argument parsing and cleanup
if [ -n "$1" ]; then
	OUTPUT_FILE=${1%.pcap}
  	FILTER="${@:2}"
fi

# Minimalist & Clean UI Handover
echo "Initializing Docker Engine & Preparing Sniffer Environment..."
echo "Press [Ctrl+C] at any time to gracefully stop the capture."
echo "-----------------------------------------------------------------"

# Launching the core C++ engine
sudo docker run --rm --network host --cap-add NET_RAW --cap-add NET_ADMIN -v $(pwd):/output ardaenfalabaci/cpp-sniffer:v1.0 /output/$OUTPUT_FILE $FILTER
