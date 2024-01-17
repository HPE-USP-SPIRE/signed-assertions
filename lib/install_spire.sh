#!/bin/bash
set -e

GREEN='\033[0;32m'
CLEAR='\033[0m'

if [ -d "/opt/spire-signed-assertions" ]; then
  echo -e "/opt/spire-signed-assertions already exists. Ignoring SPIRE installation!\n"
else
  echo -e "${GREEN}Downloading modified SPIRE...${CLEAR}"
  cd /opt
  git clone https://github.com/HPE-USP-SPIRE/spire-signed-assertions.git

  echo -e "${GREEN}Installing modified SPIRE...${CLEAR}"
  cd /opt/spire-signed-assertions
  make build

  #add to sudoer
  # if grep -Fq "/opt/spire/bin:" /etc/sudoers
  # then
  #   echo -e "/opt/spire/bin already in sudoers file.\n"
  # else
  #   sed -i 's/secure_path=\"/secure_path=\"\/opt\/spire\/bin:/' /etc/sudoers
  #   source ~/.bashrc
  #   echo -e "## SPIRE installed ##\n"
  # fi
fi
