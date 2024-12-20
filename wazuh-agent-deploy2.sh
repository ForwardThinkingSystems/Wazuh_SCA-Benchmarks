#!/bin/bash

WAZUH_AGENT_VERSION="4.8.1-1"
WAZUH_AGENT_GROUP='Linux_Servers'
CIS_PROFILE_URL='https://raw.githubusercontent.com/ForwardThinkingSystems/Wazuh_SCA-Benchmarks/main/cis_rhel8_linux.yml'
CIS_PROFILE_PATH='/var/ossec/ruleset/sca/cis_rhel8_linux.yml'
SHARED_CONFIG_PATH='/var/ossec/etc/shared/Linux_Servers/cis_rhel8_linux-FTS.yml'

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

log_message "Installing Wazuh Agent"

sudo rpm --import https://packages.wazuh.com/key/GPG-KEY-WAZUH

sudo cat > /etc/yum.repos.d/wazuh.repo << EOF
[wazuh]
gpgcheck=1
gpgkey=https://packages.wazuh.com/key/GPG-KEY-WAZUH
enabled=1
name=EL-\$releasever - Wazuh
baseurl=https://packages.wazuh.com/4.x/yum/
protect=1
EOF

sudo WAZUH_MANAGER='10.254.254.240' WAZUH_AGENT_GROUP='Linux_Servers' dnf install wazuh-agent

log_message "Configuring Wazuh Agent Service"
sudo systemctl daemon-reload
sudo systemctl enable wazuh-agent
sudo systemctl start wazuh-agent
check_error "Failed to start Wazuh Agent"

log_message "Setting up CIS profile"
sudo rm -f "/var/ossec/ruleset/sca/cis_centos8_linux.yml"
sudo curl "$CIS_PROFILE_URL" -o "$CIS_PROFILE_PATH"
check_error "Failed to download CIS profile"

sudo mkdir -p "/var/ossec/etc/shared/Linux_Servers/"
sudo cp -f "$CIS_PROFILE_PATH" "$SHARED_CONFIG_PATH"
check_error "Failed to copy CIS profile to shared directory"

log_message "Setup CIS profile - Completed"
sudo systemctl restart wazuh-agent
check_error "Failed to restart Wazuh Agent"

log_message "Wazuh Agent deployment completed successfully"
