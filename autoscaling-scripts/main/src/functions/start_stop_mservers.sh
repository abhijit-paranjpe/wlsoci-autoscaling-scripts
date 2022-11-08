#!/usr/bin/env bash

# Copyright (c) 2022, Oracle and/or its affiliates.
# Licensed under the Universal Permissive License v1.0 as shown at https://oss.oracle.com/licenses/upl.
# 
# Utility script to start and stop individual managed server by index
# Params:
#   managed_server_node_index: index of the managed server that needs to be stopped or started
#   action - start/stop managed server
#


log_file="/tmp/$2_server.log"
if [[ -f $log_file ]]; then
  rm $log_file
fi
exec 2>&1 1>${log_file}

# replace the variables
managed_server_node_index=$1
action=$2

echo $action"ing operation<<: $(date)"

server_name_prefix=$(python3 /opt/scripts/databag.py wls_ms_server_name)
server_name=$server_name_prefix$managed_server_node_index
wls_admin_user=$(python3 /opt/scripts/databag.py wls_admin_user)

admin_host_name=$(python3 /opt/scripts/databag.py wls_admin_host)
admin_port=$(python3 /opt/scripts/databag.py wls_admin_port)
wls_connect_url="t3://$admin_host_name:$admin_port"

wls_password=$(python3 /opt/scripts/wls_credentials.py wlsPassword)


if [[ "$action" == "start" ]]; then
  echo -e $wls_password | /u01/app/oracle/middleware/oracle_common/common/bin/wlst.sh -skipWLSModuleScanning /opt/scripts/manage_servers.py start_server $wls_admin_user $wls_connect_url $server_name
  exit_code=$?

  if [[ $exit_code -ne 0 ]]; then
      echo "Failed to start server $server_name [$exit_code]"
      exit $exit_code
  fi

  # Start the second managed server
  server_name=${server_name}_2
  echo -e $wls_password | /u01/app/oracle/middleware/oracle_common/common/bin/wlst.sh -skipWLSModuleScanning /opt/scripts/manage_servers.py start_server $wls_admin_user $wls_connect_url $server_name
  exit_code=$?

  if [[ $exit_code -ne 0 ]]; then
      echo "Failed to start server $server_name [$exit_code]"
      exit $exit_code
  fi
elif [[ "$action" == "stop" ]]; then
  echo -e $wls_password | /u01/app/oracle/middleware/oracle_common/common/bin/wlst.sh -skipWLSModuleScanning /opt/scripts/manage_servers.py stop_server $wls_admin_user $wls_connect_url $server_name
  exit_code=$?

  if [[ $exit_code -ne 0 ]]; then
      echo "Failed to stop server $server_name [$exit_code]"
      exit $exit_code
  fi

  # Stop the second managed server
  server_name=${server_name}_2
  echo -e $wls_password | /u01/app/oracle/middleware/oracle_common/common/bin/wlst.sh -skipWLSModuleScanning /opt/scripts/manage_servers.py stop_server $wls_admin_user $wls_connect_url $server_name
  exit_code=$?

  if [[ $exit_code -ne 0 ]]; then
      echo "Failed to stop server $server_name [$exit_code]"
      exit $exit_code
  fi

else
  echo "Action [{0}}] not supported"
  exit 1
fi

exec 1>&2 2>&-

#echo "Successfully performed $action for $server_name"
echo $action"ing operation>>: $(date)"
