.#!/bin/bash

# Function to edit or create a file in /etc/modprobe.d/ directory
edit_modprobe_conf() {
    local module_name=$1
    local conf_file="/etc/modprobe.d/${module_name}.conf"
    local install_line="install ${module_name} /bin/true"

    echo "Editing or creating ${conf_file}..."
    echo "${install_line}" | sudo tee "${conf_file}" > /dev/null
}

# Function to unload a module
unload_module() {
    local module_name=$1

    echo "Unloading ${module_name} module..."
    sudo rmmod "${module_name}"
}

# Function to edit sudoers file
edit_sudoers() {
    local custom_log_path=$1
    local sudoers_file="/etc/sudoers.d/custom_log"

    echo "Editing sudoers file..."
    echo "Defaults logfile=\"${custom_log_path}\"" | sudo tee "${sudoers_file}" > /dev/null
    sudo chmod 440 "${sudoers_file}"
}


# Function to set up AIDE
# Function to set up AIDE
setup_aide() {
    echo "Setting up AIDE..."
    # Install AIDE
    sudo dnf install aide -y
    # Initialize AIDE
    sudo aide --init
    # Create a symbolic link to the new AIDE database
    sudo ln -s /var/lib/aide/aide.db.new.gz /var/lib/aide/aide.db.gz
    # Add cron job for AIDE check
	# Define the cron command
	cron_command="0 5 * * * /usr/sbin/aide --check &> /dev/null"

	# Check if the cron command already exists in the crontab for the root user
	if ! crontab -u root -l | grep aide; then
    	# If it doesn't exist, add the cron command to the crontab for the root user
    	(crontab -u root -l; echo "$cron_command") | crontab -u root -
    	echo "Cron job added successfully."
	else
	    # If it already exists, print a message
	    echo "Cron job already exists. No changes made."
	fi
}

# Function to edit /etc/issue file
edit_issue_file() {
    local issue_contents="Authorized users only. All activity may be monitored and reported."
    echo "Editing /etc/issue file..."
    echo "${issue_contents}" | sudo tee /etc/issue.net > /dev/null
}

# Function to update SSH configuration
update_ssh_config() {
# Define the new banner path
new_banner="/etc/issue.net"
# Backup the original sshd_config file
cp /etc/ssh/sshd_config /etc/ssh/sshd_config.bak
# Update the sshd_config file with the new banner path
sed -i "s|^#Banner none|Banner $new_banner|" /etc/ssh/sshd_config
# Restart the SSH service to apply the changes
sudo systemctl restart sshd.service

echo "SSH banner updated to $new_banner"
}

# Function to create /etc/ssh/fts_banner file
create_ssh_banner() {
    local banner_contents="Forward Thinking Systems LLC\nAuthorized uses only. All activity may be monitored and reported............................."

    echo "Creating /etc/ssh/fts_banner file..."
    echo -e "${banner_contents}" | sudo tee /etc/ssh/fts_banner > /dev/null
}

check_and_add_sysctl() {
    echo "Checking and adding kernel.randomize_va_space in /etc/sysctl.conf and /etc/sysctl.d/*"
    
    # Define the sysctl line
    sysctl_line="kernel.randomize_va_space = 2"
    
    # Check if the line exists in /etc/sysctl.conf or /etc/sysctl.d/*
    if grep -Rh "^$sysctl_line" /etc/sysctl.conf /etc/sysctl.d/* >/dev/null; then
        # If the line exists, print a message
        echo "Sysctl setting already exists. No changes made."
    else
        # If the line doesn't exist, add it to /etc/sysctl.conf
        echo "$sysctl_line" | sudo tee -a /etc/sysctl.conf
        echo "Sysctl setting added successfully."
        
        # Apply the changes
        sudo sysctl -p
    fi
}

#-------------Script--Start

echo "Updating CIS Benchmarks"

rm -f /var/ossec/ruleset/sca/cis_centos8_linux.yml
curl https://raw.githubusercontent.com/ForwardThinkingSystems/Wazuh_SCA-Benchmarks/main/cis_rhel8_linux.yml -o /var/ossec/ruleset/sca/cis_rhel8_linux.yml
sudo systemctl restart wazuh-agent

#----------------------Edit or create modprobe configurations
edit_modprobe_conf "cramfs"
edit_modprobe_conf "vfat" https://bugzilla.redhat.com/show_bug.cgi?id=1927019
edit_modprobe_conf "squashfs"
edit_modprobe_conf "udf"
edit_modprobe_conf "usb-storage"

#----------------------Unload modules
unload_module "cramfs"
unload_module "vfat"
unload_module "squashfs"
unload_module "udf"
unload_module "usb-storage"

#----------------------Edit sudoers file
edit_sudoers "/var/log/sudoers.log"

#----------------------Set up AIDE
setup_aide

#----------------------Edit /etc/issue file
edit_issue_file

#----------------------Create /etc/ssh/fts_banner file
create_ssh_banner

#----------------------Update SSH configuration
update_ssh_config

#----------------------Mask NFT Tables 
sudo systemctl --now mask nftables

#----------------------disable All Radios 
sudo nmcli radio all off

#----------------------enable ASLR - kernel.randomize_va_space = 2
check_and_add_sysctl

#----------------------Ensure remote login warning banner is configured properly
echo "Authorized uses only. All activity may be monitored and reported" > /etc/issue.net

#----------------------enable FUTURE crypto policy - This should be tested and enabled as needed
echo "min_dh_size = 2048" > /etc/crypto-policies/policies/modules/2048KEYS.pmod
echo "min_rsa_size = 2048" >> /etc/crypto-policies/policies/modules/2048KEYS.pmod
update-crypto-policies --set FUTURE:2048KEYS


#----------------------Enable martian packet logs -  A martian packet is a packet with a source address which is obviously wrong - nothing could possibly be routed back to that address.

sysctl -w net.ipv4.conf.all.log_martians=1
sysctl -w net.ipv4.conf.default.log_martians=1
sysctl -w net.ipv4.route.flush=1

#----------------------Disable IPv6 RA reponses 
sysctl -w net.ipv6.conf.all.accept_ra=0
sysctl -w net.ipv6.conf.default.accept_ra=0
sysctl -w net.ipv6.route.flush=1

#----------------------Ensure IPv6 default deny firewall policy
ip6tables -P INPUT DROP; # ip6tables -P OUTPUT DROP; # ip6tables -P FORWARD DROP
ip6tables -A INPUT -i lo -j ACCEPT # ip6tables -A OUTPUT -o lo -j ACCEPT # ip6tables -A INPUT -s ::1 -j DROP

#----------------------SSHD modifications 

#----------------------get the current date and time in YYYY-MM-DD_HH-MM-SS format
timestamp=$(date +"%Y-%m-%d_%H-%M-%S")

#----------------------copy the original file to a backup file with the timestamp
cp /etc/ssh/sshd_config /etc/ssh/sshd_config_$timestamp

#----------------------disable X11 forwarding
sudo sed -i 's/^#*X11Forwarding yes/X11Forwarding no/' /etc/ssh/sshd_config

#----------------------set max auth retries to 4
sudo sed -i 's/^#*MaxAuthTries [0-9]*/MaxAuthTries 4/' /etc/ssh/sshd_config

#----------------------set login grace time to 60
sudo sed -i 's/^#*LoginGraceTime [0-9]*/LoginGraceTime 60/' /etc/ssh/sshd_config

#----------------------crontab Permissions
sudo chown root:root /etc/crontab
sudo chmod og-rwx /etc/crontab
sudo chown root:root /etc/cron.hourly
sudo chmod og-rwx /etc/cron.hourly
sudo chown root:root /etc/cron.daily
sudo chmod og-rwx /etc/cron.daily
sudo chown root:root /etc/cron.weekly 
sudo chmod og-rwx /etc/cron.weekly
sudo chown root:root /etc/cron.d
sudo chmod og-rwx /etc/cron.d

echo "FTS CIS Baseline Setup completed successfully!"


