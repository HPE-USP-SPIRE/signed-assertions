#!/bin/bash

BASE_PATH=$PWD

#When running only this script, uncomment below
# cd ..
# BASE_PATH=$PWD


cd "${BASE_PATH}/Assertingwl-mTLS"
docker build . -t asserting-wl
sleep 2

cd "${BASE_PATH}/subject_workload"
docker build . -t subject-wl
sleep 2

cd "${BASE_PATH}/target_workload"
docker build . -t target-wl
sleep 2

cd "${BASE_PATH}/middle-tier"
docker build . -t middle-tier
sleep 2

#docker stop $(docker ps -a -q)
#docker rm $(docker stop $(docker ps -a -q))
#docker rmi -f asserting-wl subject-wl middle-tier target-wl
#docker rmi $(docker images -q)