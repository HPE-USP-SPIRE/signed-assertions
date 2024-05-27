#!/bin/bash
#
# This script downloads SPIRE with the LSVID implementation
#

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
  cd /spire-signed-assertions
  make build
fi