# Configuring and installing manually the Proof of Concept

0. Configure OKTA application

1. Configure each workload manually
  * Each workload contains a hidden .cfg file. Change the IP address in all of them.
  * Change the OKTA credentials on Subject Workload .cfg file.

2. Install SPIRE (sudo required)
```
cd /opt
git clone https://github.com/spiffe/spire.git
cd /opt/spire
make build
sed -i 's/secure_path=\"/secure_path=\"\/opt\/spire\/bin:/' /etc/sudoers
source ~/.bashrc
```

3. Install Docker (sudo required)
  * Use [this link](https://docs.docker.com/engine/install/ubuntu/) for Ubuntu distribution
  * Use [this link](https://docs.docker.com/engine/install/debian/) for Debian distribution

4. Add user to Docker group (recommended)
```
sudo usermod -aG docker $USER
su - $USER
```
5. Start SPIRE environment (sudo required)

* Copy **start_spire_env.sh** on **/lib** to **/opt/spire** and execute it
```
sudo cp /lib/start_spire_env.sh /opt/spire
cd /opt/spire
sudo bash start_spire_env.sh
```

6. Build Docker Containers
```
cd ./Assertingwl-mTLS
docker build . -t asserting-wl

cd ..
cd ./subject_workload
docker build . -t subject-wl

cd ..
cd ./target_workload
docker build . -t target-wl

cd ..
cd ./middle-tier
docker build . -t middle-tier
```

7. Run Docker images
```
docker run -p 8443:8443 -v /tmp/spire-agent/public/api.sock:/tmp/spire-agent/public/api.sock -d asserting-wl

docker run -p 8080:8080 -v /tmp/spire-agent/public/api.sock:/tmp/spire-agent/public/api.sock -d subject-wl

docker run -p 8445:8445 -v /tmp/spire-agent/public/api.sock:/tmp/spire-agent/public/api.sock -d middle-tier

docker run -p 8444:8444 -v /tmp/spire-agent/public/api.sock:/tmp/spire-agent/public/api.sock -d target-wl
```
8. Test application
