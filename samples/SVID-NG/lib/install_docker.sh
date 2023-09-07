#!/bin/bash
set -e
DISTRO=''

function get_distro(){
DISTRO=$(lsb_release -d | awk -F "\t" '{print $2}')
if [[ $DISTRO =~ "Ubuntu" ]]; then
  DISTRO="Ubuntu"
elif [[ $DISTRO =~ "Debian" ]]; then
  DISTRO="Debian"
else
  echo 'Distro not found. Closing application...'
  exit 1
fi
}
get_distro


function install_docker(){
# apt-get remove docker docker-engine docker.io containerd runc
# rm /etc/apt/sources.list.d/docker.list
# rm /etc/apt/keyrings/docker.gpg
# rm -rf /var/lib/docker
# rm -rf /var/lib/containerd

if [ "$(command -v docker)" ]; then
  echo -e "Docker already installed."
else
  apt update
  apt-get install ca-certificates curl gnupg lsb-release -y
  mkdir -p /etc/apt/keyrings
  curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo gpg --dearmor -o /etc/apt/keyrings/docker.gpg
  if [ $DISTRO == "Ubuntu" ]; then
    echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/ubuntu \
    $(lsb_release -cs) stable" | sudo tee /etc/apt/sources.list.d/docker.list > /dev/null
  elif [ $DISTRO == "Debian" ]; then
    echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/debian \
    $(lsb_release -cs) stable" | sudo tee /etc/apt/sources.list.d/docker.list > /dev/null
  else
    echo "This distribution is not included in our use cases. Docker installation unsuccessful..."
    exit 1
  fi

  apt update
  apt-get install docker-ce docker-ce-cli containerd.io docker-compose-plugin -y

  echo -e "Docker installed! Please reboot you machine when the installation is done."
fi
}
install_docker