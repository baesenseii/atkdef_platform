#!/bin/sh

#start-up script (modified for docker container)

service apache2 start
service ssh start
service cron start
service wazuh-agent start
tail -f /dev/null

