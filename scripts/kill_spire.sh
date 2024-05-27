#!/bin/bash
#
# This script kills SPIRE Agent/Server processes
# AND remove temporary data
#

sudo kill -9 $(ps -ef | grep "spire-agent" | grep -v grep | awk '{print $2}')
sudo kill -9 $(ps -ef | grep "spire-server" | grep -v grep | awk '{print $2}')
sudo rm -rf /opt/spire/.data
echo "Spire Agent/Server killed"