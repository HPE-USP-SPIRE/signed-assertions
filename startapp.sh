#!/bin/bash

# docker stop $(docker ps -a -q)

# cd Assertingwl-mTLS/
# docker build . -t asserting-wl
# docker run -p 8443:8443 -v /tmp/spire-agent/public/api.sock:/tmp/spire-agent/public/api.sock -d asserting-wl

cd ./metasrv/
docker build . -t metasrv
docker run -p 8888:8888  -d metasrv
