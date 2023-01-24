#!/bin/bash

if [ -d "/opt/spire" ]; then
  echo -e "/opt/spire already exists. Ignoring SPIRE installation!\n"
  sleep 2
else
  echo -e "## Installing SPIRE ##"
  sleep 2
  cd /opt
  git clone https://github.com/spiffe/spire.git
  cd /opt/spire
  make build
  if grep -Fq "/opt/spire/bin:" /etc/sudoers
  then
    echo -e "/opt/spire/bin already in sudoers file.\n"
  else
    sed -i 's/secure_path=\"/secure_path=\"\/opt\/spire\/bin:/' /etc/sudoers
    source ~/.bashrc
    echo -e "## SPIRE installed ##\n"
  fi
fi
