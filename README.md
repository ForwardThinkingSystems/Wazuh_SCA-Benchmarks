# Wazuh_SCA-Benchmarks

## Deploy the agent with the appropriate CIS profile

```
# Download the script locally
curl -s -L https://raw.githubusercontent.com/ForwardThinkingSystems/Wazuh_SCA-Benchmarks/refs/heads/main/wazuh-agent-deploy.sh -o wazuh-agent-deploy.sh

# Set execute permissions (optional but recommended)
chmod +x wazuh-agent-deploy.sh

# Run the script with sudo
sudo bash wazuh-agent-deploy.sh

```

## Add Nginx FIM config (Nginx Servers only)

```curl -sSL https://raw.githubusercontent.com/ForwardThinkingSystems/Wazuh_SCA-Benchmarks/main/Nginx_FIM-deploy_config.sh | bash```

## Deploy the AuditD setup

```sudo curl -s -L https://raw.githubusercontent.com/ForwardThinkingSystems/Wazuh_SCA-Benchmarks/main/FTS-Audit-Rules.sh | bash```

## Deploy the CIS setup script (Run as root 'sudo su')

```curl -s -L https://raw.githubusercontent.com/ForwardThinkingSystems/Wazuh_SCA-Benchmarks/main/FTS-CIS-Profile.sh | bash```

### ------------------------------------------------------------------------------------

## Upgrade agent - Use this if you already have an older agent installed

```sudo curl -s -L https://raw.githubusercontent.com/ForwardThinkingSystems/Wazuh_SCA-Benchmarks/refs/heads/main/wazuh_agent_upgrade.sh | bash```
