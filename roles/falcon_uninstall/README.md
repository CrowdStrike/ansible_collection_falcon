Uninstall
=========

This role uninstalls the CrowdStrike Falcon Sensor.

Requirements
------------

Ansible 2.11 or higher

Role Variables
--------------

The following variables are currently supported:

 * `falcon_windows_uninstall_args` - Additional Windows uninstall arguments (string, default: `/norestart`)
 * `falcon_windows_become_method` - The way to become a privileged user on Windows (string, default: `runas`)
 * `falcon_windows_become_user` - The privileged user to uninstall the sensor on Windows (string, default: `SYSTEM`)

See [defaults/main.yml](defaults/main.yml) for more details on these variables.

Dependencies
------------

Privilege escalation (sudo) is required for this role to function properly.

Example Playbooks
----------------

This example uninstalls the Falcon Sensor:

```yaml
---
- hosts: all
  roles:
  - role: crowdstrike.falcon.falcon_uninstall
```

License
-------

[License](https://github.com/crowdstrike/ansible_collection_falcon/blob/main/LICENSE)

Author Information
------------------

CrowdStrike Solution Architects
