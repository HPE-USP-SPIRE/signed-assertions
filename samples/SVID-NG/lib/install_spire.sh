#!/bin/bash
set -e

if [ -d "/opt/spire" ]; then
  echo -e "/opt/spire already exists. Ignoring SPIRE installation!\n"
  sleep 2
else
  sleep 2
  #download SPIRE
  cd /opt
  git clone https://github.com/spiffe/spire.git

  #install spire
  cd /opt/spire
  make build

  #configure SPIRE
  echo 'agent {
      data_dir = "./.data"
      log_level = "DEBUG"
      server_address = "127.0.0.1"
      server_port = "8081"
      socket_path ="/tmp/spire-agent/public/api.sock"
      trust_bundle_path = "./conf/agent/dummy_root_ca.crt"
      trust_domain = "example.org"
  }

  plugins {
      NodeAttestor "join_token" {
          plugin_data {
          }
      }
      KeyManager "disk" {
          plugin_data {
              directory = "./.data"
          }
      }
      WorkloadAttestor "unix" {
          plugin_data {
          }
      }
      WorkloadAttestor "k8s" {
          plugin_data {
              kubelet_read_only_port = "10255"
          }
      }

      WorkloadAttestor "docker" { plugin_data { } }
  }' > /opt/spire/conf/agent/agent.conf

  #add to sudoer
  if grep -Fq "/opt/spire/bin:" /etc/sudoers
  then
    echo -e "/opt/spire/bin already in sudoers file.\n"
  else
    sed -i 's/secure_path=\"/secure_path=\"\/opt\/spire\/bin:/' /etc/sudoers
    source ~/.bashrc
    echo -e "## SPIRE installed ##\n"
  fi
fi
