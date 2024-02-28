#!/bin/bash

OSSSEC_Config_nginx_Source_PATH='https://raw.githubusercontent.com/ForwardThinkingSystems/Wazuh_SCA-Benchmarks/main/Nginx_ossec.conf'
OSSSEC_Config_nginx_LOCAL_PATH= '/var/ossec/etc/ossec.conf'

# Function to display messages
log_message() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1"
}

# Function to check for errors and exit if encountered
check_error() {
    if [ $? -ne 0 ]; then
        log_message "Error: $1"
        exit 1
    fi
}

# Check if Wazuh agent service is running
if sudo systemctl is-active --quiet wazuh-agent; then
    echo "wazuh Agent Service is active - Proceeding with the config file deployment"
    sudo rm -f "/var/ossec/etc/ossec.conf"
    sudo curl "$OSSSEC_Config_nginx_Source_PATH" "$OSSSEC_Config_nginx_LOCAL_PATH"
    check_error "Failed to copy OSSEC Config file"
    log_message "OSSEC Config file deployment - Completed"   
else
    echo "wazuh Agent Service is not active. Please run the Deploy Wazuh agent script"
fi

sudo systemctl restart wazuh-agent
check_error "Failed to restart Wazuh Agent"
