#!/bin/bash

# Minimalist & Clean UI Handover
echo "Initializing Docker Engine & Interactive Sniffer Environment..."
echo "Press [Ctrl+C] at any time to gracefully stop the capture."
echo "-----------------------------------------------------------------"

# -it bayrağı eklendi (Interactive Terminal)
# En sona /output/ eklendi (C++ koduna gizli klasör yolu olarak gidecek)
sudo docker run -it --rm --network host --cap-add NET_RAW --cap-add NET_ADMIN -v $(pwd):/output ardaenfalabaci/cpp-sniffer:v1.0 /output/
