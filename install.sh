#!/bin/bash

# Update package list and install system dependencies
sudo apt update
sudo apt install -y iproute2 curl ufw lsof net-tools procps grep gawk sed coreutils python3-tk pipx

# Ensure pipx is set up properly
pipx ensurepath

# Optionally, create a virtual environment for your application using pipx
pipx install --python python3 tkinter

# Inform the user
clear
echo "👻 Ghosint - Live OPSEC Monitor dependencies are installed!"
echo "You can now run your Python script directly:"
echo "python3 liveOpsec.py"

