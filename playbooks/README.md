# Playbook Examples

This directory contains example Ansible playbooks demonstrating how to use the CrowdStrike Falcon collection. These examples should be customized for your specific environment and requirements.

## Available Playbooks

### redhat_insights_yara.yml

Downloads CrowdStrike YARA hunting rules and deploys them to Red Hat Insights Client systems. This playbook:

- Downloads YARA rules for Linux to localhost (one time)
- Distributes the rules to all hosts in the `yara` host group
- Unpacks rules into the third-party signatures directory used by Red Hat Insights Client
