Installation
=========

This role will install or uninstall the CrowdStrike Falcon Sensor.

Requirements
------------

Ansible 2.10 or higher

Role Variables
--------------

The following variables are currently supported:

### Falcon Installation

 * `falcon_cid` - Your Falcon Customer ID (CID) (string, default: null)
 * `falcon_provisioning_token` - Falcon Installation Token (string, default: null)
 * `falcon_install_method` - The installation method for installing the sensor (string, default: api)
 * `falcon_gpg_key` - Location of the Falcon GPG Key file (string, default: null)
 * `falcon_remove_agent_id` - Remote the Falcon Agent ID (AID) (bool, default: false)
 * `falcon_cloud` - CrowdStrike API URL for downloading the Falcon sensor (string, default: `api.crowdstrike.com`)
 * `falcon_client_id` - CrowdStrike OAUTH Client ID (string, default: null)
 * `falcon_client_secret` - CrowdStrike OAUTH Client Secret (string, default: null)
 * `falcon_install_tmp_dir` - Temporary Linux and MacOS download and installation directory for the Falson Sensor (string, default: `/tmp/`)
 * `falcon_download_url` - URL for downloading the sensor (string, default: null)
 * `falcon_retries` - Number of attempts to download the sensor (int, default: 3)
 * `falcon_delay` - Number of seconds before trying another download attempt (int, default: 3)
 * `falcon_windows_install_retries` - Number of times to retry sensor install on windows (int, default: 10)
 * `falcon_windows_install_delay` - Number of seconds to wait to retry sensor install on windows in the event of a failure (int, default: 120)
 * `falcon_windows_tmp_dir` - Temporary Windows download and installation directory for the Falson Sensor (string, default: `%SYSTEMROOT%\\Temp`)
 * `falcon_windows_install_args` - Additional Windows install arguments (string, default: `/norestart`)
 * `falcon_windows_uninstall_args` - Additional Windows uninstall arguments (string, default: `/norestart`)
 * `falcon_windows_become_method` - The way to become a privileged user on Windows (string, default: `runas`)
 * `falcon_windows_become_user` - The privileged user to install the sensor on Windows (string, default: `SYSTEM`)
 * `falcon_uninstall` - Uninstall the Falcon Sensor (bool, default: false)

See [default/main.yml](default/main.yml) for more details on these variables.

Dependencies
------------

Privilege escalation (sudo) is required for this role to function properly.

Example Playbooks
----------------

This example installs the Falcon Sensor:

```yaml
---
- hosts: all
  roles:
  - role: crowdstrike.falcon.falcon_installation
  vars:
    falcon_client_id: <Falcon_UI_OAUTH_client_id>
    falcon_client_secret: <Falcon_UI_OAUTH_client_secret>
```

This example uninstalls the Falcon Sensor:

```yaml
---
- hosts: all
  roles:
  - role: crowdstrike.falcon.falcon_installation
  vars:
    falcon_uninstall: true
```

License
-------

[Unlicense](https://github.com/crowdstrike/ansible_collection_falcon/blob/main/LICENSE)

Author Information
------------------

CrowdStrike Solutions Architects
