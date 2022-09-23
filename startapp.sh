#!/bin/bash

cd ./metasrv/
docker build . -t metasrv
docker run -p 8888:8888  -d metasrv

cd ../client
go build -o assertgen main.go

