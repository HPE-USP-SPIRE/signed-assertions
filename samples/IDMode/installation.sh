#!/bin/bash

set -e

function DA-SVID_inst(){
skip_SPIRE=''
skip_DOCKER=''

### Reading config file
echo -e "## Reading config file ##\n"
sleep 1
while IFS= read -r LINE
do
  LINE=$(echo $LINE | tr '[:lower:]' '[:upper:]')
  if grep -q "SPIRE" <<< "$LINE"; then
    TMP=${LINE#*=}
    if [ $TMP == 'TRUE' ] || [ $TMP == 'FALSE' ]; then
      skip_SPIRE=$TMP
    else
      trap "Error reading config file. Must be string TRUE or FALSE." EXIT
    fi
  elif grep -q "DOCKER" <<< "$LINE"; then
    TMP=${LINE#*=}
    if [ $TMP == 'TRUE' ] || [ $TMP == 'FALSE' ]; then
      skip_DOCKER=$TMP
    else
      trap "Error reading config file. Must be string TRUE or FALSE." EXIT
    fi
  else
    continue
  fi
done < "./.cfg"

### Installation section 
LIB_PATH="./lib"

if [ $skip_SPIRE == 'FALSE' ]; then
  sudo bash $LIB_PATH/install_spire.sh
fi
if [ $skip_DOCKER == 'FALSE' ]; then
  sudo bash $LIB_PATH/install_docker.sh
fi
}
DA-SVID_inst

echo -e "Adding <user> to docker group.\n"
usr=$(whoami)
sudo usermod -aG docker $usr
su - $usr

echo "Complete\n"