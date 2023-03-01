#!/bin/bash
LIB_PATH="./lib"
set -e

echo -e "Installing APT packages..."
sudo apt update
sudo apt install build-essential curl git make -y
echo -e "APT packages Installed!"

echo -e "Installing SPIRE..."
sudo bash $LIB_PATH/install_spire.sh

echo -e "Installing Docker..."
sudo bash $LIB_PATH/install_docker.sh

echo -e "Adding user to docker group. Press Ctrl+C if you are not installing docker.\n"
usr=$(whoami)
sudo usermod -aG docker $usr

echo "Done!"