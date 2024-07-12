#!/bin/bash
#
# This scripts generates the basic configuration file used on the proof of concept.
# CLIENT_ID, CLIENT_SECRET and ISSUER are values obtained from OKTA.
#

cat << EOF > ./.cfg
SOCKET_PATH=unix:///tmp/spire-agent/public/api.sock
TRUST_DOMAIN=example.org
PEM_PATH=./keys/oauth.pem
PROOF_LEN=80
MINT_ZKP=false
ADD_ZKP=false
CLIENT_ID=<CLIENT_ID>
CLIENT_SECRET=<CLIENT_SECRET>
ISSUER=https://dev-<NUMBER>.okta.com/oauth2/default
HOSTIP=<IP>
ASSERTINGWLIP=<IP>:8443
TARGETWLIP=<IP>:8444
MIDDLETIERIP=<IP>:8445
MIDDLE_TIER2_IP=<IP>:8446
MIDDLE_TIER3_IP=<IP>:8447
MIDDLE_TIER4_IP=<IP>:8448
MIDDLE_TIER5_IP=<IP>:8449
EOF

echo "Base configuration template generated"