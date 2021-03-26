# Ansible Collection - crowdstrike.falcon

This collection is focused on downloading, installing, and removing CrowdStrike's Falcon sensor.

# Installation

To install the collection from Ansible Galaxy:

```
ansible-galaxy collection install crowdstrike.falcon
```

## Installing on MacOS

Due to Apple's decision to require Mobile Device Management (MDM) software to install kernel extensions without user prompting,
the ansible collection with its roles will only be able to run on macOS in an interactive session which severely limits the
power of Ansible.

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
