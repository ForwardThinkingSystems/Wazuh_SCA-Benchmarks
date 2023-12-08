#!/bin/bash
sudo dnf install audit -y
#sudo cp /usr/share/audit/sample-rules/30-stig.rules /home/lxadmin/30-stig.rules
sudo curl https://raw.githubusercontent.com/ForwardThinkingSystems/Wazuh_SCA-Benchmarks/main/fts-audit.rules -o /etc/audit/rules.d/fts-audit.rules
sudo service auditd reload
