#!/bin/bash

# Variables
WAZUH_AGENT_VERSION="4.9.2-1"
WAZUH_AGENT_GROUP='Linux_Servers'

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

log_message "Stopping Wazuh Agent Service"
sudo systemctl stop wazuh-agent
check_error "Failed to stop Wazuh Agent"

log_message "Downloading new version of Wazuh Agent"
curl -o wazuh-agent-${WAZUH_AGENT_VERSION}.x86_64.rpm https://packages.wazuh.com/4.x/yum/wazuh-agent-${WAZUH_AGENT_VERSION}.x86_64.rpm
check_error "Failed to download Wazuh Agent package"

log_message "Upgrading Wazuh Agent"
sudo dnf localinstall -y wazuh-agent-${WAZUH_AGENT_VERSION}.x86_64.rpm
check_error "Failed to upgrade Wazuh Agent"

log_message "Configuring Wazuh Agent Service"
sudo systemctl daemon-reload
sudo systemctl enable wazuh-agent
check_error "Failed to enable Wazuh Agent service"

sudo systemctl start wazuh-agent
check_error "Failed to start Wazuh Agent"

log_message "Wazuh Agent upgraded successfully!"
