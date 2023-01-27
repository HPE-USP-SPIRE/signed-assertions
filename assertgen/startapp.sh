#!/bin/bash

docker rmi keysrv -f

cd ./keysrv/
docker build . -t keysrv
docker run -p 8888:8888  -d keysrv

cd ../
go build -o assertgen main.go

