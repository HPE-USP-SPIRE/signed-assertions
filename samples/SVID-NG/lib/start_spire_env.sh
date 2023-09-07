#!/bin/bash

reset_spire() {
     kill -9 $(ps -ef | grep "spire-agent" | grep -v grep | awk '{print $2}')
     kill -9 $(ps -ef | grep "spire-server" | grep -v grep | awk '{print $2}')
     rm -rf /opt/spire/.data
}
reset_spire

sleep 1

start_spire_server () {
    # Start the SPIRE Server as a background process
    echo "Starting spire-server..."
    sleep 1
    spire-server run -config /opt/spire/conf/server/server.conf & 
    sleep 2
}
start_spire_server


generate_jointoken () {
# Generate a one time Join Token. 
echo "Generating token..."
sleep 1
tmp=$( spire-server token generate -spiffeID spiffe://example.org/host)
echo $tmp
token=${tmp:7}
# echo $token >> tokens.lst
echo -e "Generated token: $token.\nReady to start a new agent."
}

start_spire_agent () {
    generate_jointoken
    # Start the SPIRE Agent as a background process using the token passed by parameter.
    echo "Starting spire-agent..."
    sleep 1
    spire-agent run -joinToken $token -config /opt/spire/conf/agent/agent.conf &
    sleep 1
    token=''
}
start_spire_agent

spire-server entry create \
    -parentID spiffe://example.org/host \
    -spiffeID spiffe://example.org/asserting_wl \
    -selector docker:label:type:assertingwl

spire-server entry create \
    -parentID spiffe://example.org/host \
    -spiffeID spiffe://example.org/subject_wl \
    -selector docker:label:type:subjectwl

spire-server entry create \
    -parentID spiffe://example.org/host \
    -spiffeID spiffe://example.org/subject_mob \
    -selector docker:label:type:subjectmob

spire-server entry create \
    -parentID spiffe://example.org/host \
    -spiffeID spiffe://example.org/target_wl \
    -selector docker:label:type:targetwl

spire-server entry create \
    -parentID spiffe://example.org/host \
    -spiffeID spiffe://example.org/middletier \
    -selector docker:label:type:middletier

spire-server entry create \
    -parentID spiffe://example.org/host \
    -spiffeID spiffe://example.org/middletier2 \
    -selector docker:label:type:middletier2

spire-server entry create \
    -parentID spiffe://example.org/host \
    -spiffeID spiffe://example.org/middletier3 \
    -selector docker:label:type:middletier3

spire-server entry create \
    -parentID spiffe://example.org/host \
    -spiffeID spiffe://example.org/middletier4 \
    -selector docker:label:type:middletier4

spire-server entry create \
    -parentID spiffe://example.org/host \
    -spiffeID spiffe://example.org/middletier5 \
    -selector docker:label:type:middletier5