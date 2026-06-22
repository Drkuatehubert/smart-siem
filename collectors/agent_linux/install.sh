#!/bin/bash
# install.sh — Installe l agent comme service systemd
cp agent.py /opt/siem-agent/
systemctl enable siem-agent && systemctl start siem-agent
echo "Agent installé"
