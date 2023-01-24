#!/bin/bash

Asserting_port=''
Subject_port=8080
MT_port=''
Target_port=''

## Read config file
cp_data_config(){
while IFS= read -r LINE
do
  if grep -q "Asserting-wl port" <<< "$LINE"; then
    Asserting_port=${LINE#*=}
  elif grep -q "Target-wl port" <<< "$LINE"; then
    MT_port=${LINE#*=}
  elif grep -q "Middle-tier-wl port" <<< "$LINE"; then
    Target_port=${LINE#*=}
  else
    continue
  fi
done < "./config"
}
cp_data_config

run_containers(){
  docker run -p "${Asserting_port}:${Asserting_port}" -v /tmp/spire-agent/public/api.sock:/tmp/spire-agent/public/api.sock -d asserting-wl
  sleep 1
  docker run -p "${Subject_port}:${Subject_port}" -v /tmp/spire-agent/public/api.sock:/tmp/spire-agent/public/api.sock -d subject-wl
  sleep 1
  docker run -p "${MT_port}:${MT_port}" -v /tmp/spire-agent/public/api.sock:/tmp/spire-agent/public/api.sock -d middle-tier
  sleep 1
  docker run -p "${Target_port}:${Target_port}" -v /tmp/spire-agent/public/api.sock:/tmp/spire-agent/public/api.sock -d target-wl
  sleep 1
}
run_containers

### To run manually use below
# docker run -p 8443:8443 -v /tmp/spire-agent/public/api.sock:/tmp/spire-agent/public/api.sock -d asserting-wl
# docker run -p 8080:8080 -v /tmp/spire-agent/public/api.sock:/tmp/spire-agent/public/api.sock -d subject-wl
# docker run -p 8445:8445 -v /tmp/spire-agent/public/api.sock:/tmp/spire-agent/public/api.sock -d middle-tier
# docker run -p 8444:8444 -v /tmp/spire-agent/public/api.sock:/tmp/spire-agent/public/api.sock -d target-wl