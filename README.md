[![Ansible Lint](https://github.com/CrowdStrike/ansible_collection_falcon/actions/workflows/ansible-lint.yml/badge.svg)](https://github.com/CrowdStrike/ansible_collection_falcon/actions/workflows/ansible-lint.yml)

# Ansible Collection - crowdstrike.falcon

This collection is focused on downloading, installing, and removing CrowdStrike's Falcon sensor.

# Installation

To install the collection from Ansible Galaxy:

```
ansible-galaxy collection install crowdstrike.falcon
```

## Installing on MacOS

Apple platforms require Mobile Device Management (MDM) software to install kernel extensions
without user prompting. Ansible is only able to run on macOS in an interactive session, which means end-users will receive prompts to accept the CrowdStrike kernel modules.

# Example Playbooks

This example uninstalls the Falcon Sensor:

```yaml
---
- hosts: all
  vars:
    falcon_uninstall: true
  tasks:
    - import_role:
        name: crowdstrike.falcon.falcon_installation
```

# Contributing

All contributions are welcome!

# License

See the [Unlicense](LICENSE) for more information.
