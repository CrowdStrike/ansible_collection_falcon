# Ansible Collection - crowdstrike.falcon

This collection is focused on downloading, installing, and removing, CrowdStrike's Falcon sensor on Linux platforms. Windows and OSX coming soon.

# Installation

To install the collection from Ansible Galaxy:

```
ansible-galaxy collection install crowdstrike.falcon
```

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
