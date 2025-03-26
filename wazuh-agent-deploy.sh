#!/bin/bash

WAZUH_AGENT_GROUP='Linux_Servers'
#CIS_PROFILE_URL='https://raw.githubusercontent.com/ForwardThinkingSystems/Wazuh_SCA-Benchmarks/main/cis_rhel8_linux.yml' --- Keeping as a reference
CIS_PROFILE_URL=""
CIS_PROFILE_PATH='/var/ossec/ruleset/sca/cis_rhel8_linux.yml'
SHARED_CONFIG_PATH='/var/ossec/etc/shared/Linux_Servers/cis_rhel8_linux-FTS.yml'

# Detect AlmaLinux version
os_version=$(grep -oP '(?<=release )\d+' /etc/redhat-release)

# Define URLs for CIS benchmark files
cis_alma_linux_8="https://raw.githubusercontent.com/wazuh/wazuh/refs/heads/master/ruleset/sca/almalinux/cis_alma_linux_8.yml"
cis_alma_linux_9="https://raw.githubusercontent.com/wazuh/wazuh/refs/heads/master/ruleset/sca/almalinux/cis_alma_linux_9.yml"

# Download the correct CIS file based on the detected version
if [ "$os_version" -eq 8 ]; then
    echo "Detected AlmaLinux 8. Downloading CIS benchmark for AlmaLinux 8..."
    CIS_PROFILE_URL=$cis_alma_linux_8
elif [ "$os_version" -eq 9 ]; then
    echo "Detected AlmaLinux 9. Downloading CIS benchmark for AlmaLinux 9..."
    CIS_PROFILE_URL=$cis_alma_linux_9
else
    echo "Unsupported AlmaLinux version: $os_version"
    exit 1
fi


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

rpm --import https://packages.wazuh.com/key/GPG-KEY-WAZUH
cat > /etc/yum.repos.d/wazuh.repo << EOF
[wazuh]
gpgcheck=1
gpgkey=https://packages.wazuh.com/key/GPG-KEY-WAZUH
enabled=1
name=EL-\$releasever - Wazuh
baseurl=https://packages.wazuh.com/4.x/yum/
protect=1
EOF

dnf update

WAZUH_MANAGER="10.0.0.2" dnf install wazuh-agent

sudo systemctl daemon-reload
sudo systemctl enable wazuh-agent
sudo systemctl start wazuh-agent

log_message "Setting up CIS profile"
sudo rm -f "/var/ossec/ruleset/sca/cis_centos*_linux.yml"
sudo curl "$CIS_PROFILE_URL" -o "$CIS_PROFILE_PATH"
check_error "Failed to download CIS profile"

sudo mkdir -p "/var/ossec/etc/shared/Linux_Servers/"
sudo cp -f "$CIS_PROFILE_PATH" "$SHARED_CONFIG_PATH"
check_error "Failed to copy CIS profile to shared directory"

log_message "Setup CIS profile - Completed"
sudo systemctl restart wazuh-agent
check_error "Failed to restart Wazuh Agent"

log_message "Wazuh Agent deployment completed successfully"
