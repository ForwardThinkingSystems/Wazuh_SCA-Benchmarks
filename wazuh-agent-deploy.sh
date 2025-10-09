#!/bin/bash
WAZUH_MANAGER="10.254.254.240"
WAZUH_AGENT_GROUP='Linux_Servers'
WAZUH_PROTOCOL="tcp"

# Detect AlmaLinux version
os_version=$(grep -oP '(?<=release )\d+' /etc/redhat-release)

# Define URLs for CIS benchmark files
cis_alma_linux_8="https://raw.githubusercontent.com/wazuh/wazuh/refs/heads/master/ruleset/sca/almalinux/cis_alma_linux_8.yml"
cis_alma_linux_9="https://raw.githubusercontent.com/wazuh/wazuh/refs/heads/master/ruleset/sca/almalinux/cis_alma_linux_9.yml"

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

log_message() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1"
}

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

sudo dnf update -y

# Set environment variables for agent configuration
export WAZUH_MANAGER="$WAZUH_MANAGER"
export WAZUH_MANAGER_PORT="1514"
export WAZUH_PROTOCOL="$WAZUH_PROTOCOL"
export WAZUH_AGENT_GROUP="$WAZUH_AGENT_GROUP"

sudo -E dnf install wazuh-agent -y
check_error "Failed to install Wazuh Agent"

sudo systemctl daemon-reload
sudo systemctl enable wazuh-agent
sudo systemctl start wazuh-agent
check_error "Failed to start Wazuh Agent"

log_message "Setting up CIS profile"
sudo rm -f "/var/ossec/ruleset/sca/cis_centos*_linux.yml"
sudo curl "$CIS_PROFILE_URL" -o "/var/ossec/ruleset/sca/cis_alma_linux_${os_version}.yml"
check_error "Failed to download CIS profile"

sudo mkdir -p "/var/ossec/etc/shared/Linux_Servers/"
sudo cp -f "/var/ossec/ruleset/sca/cis_alma_linux_${os_version}.yml" "/var/ossec/etc/shared/Linux_Servers/cis_alma_linux_${os_version}-FTS.yml"
check_error "Failed to copy CIS profile to shared directory"

log_message "Setup CIS profile - Completed"

sudo systemctl restart wazuh-agent
check_error "Failed to restart Wazuh Agent"

log_message "Wazuh Agent deployment completed successfully"
