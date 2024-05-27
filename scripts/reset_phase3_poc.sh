#
# This script removes containers related to the LSVID PoC.
#

docker ps -a --filter "name=phase3_*" -q | xargs docker stop
docker ps -a --filter "name=phase3_*" -q | xargs docker rm -f

##  REMOVE dangling images AND images related to Phase3
docker image prune -f
docker images --filter=reference='phase3_*' -q | xargs -r docker rmi

bash kill_lsvid_spire.sh