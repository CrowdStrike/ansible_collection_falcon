Installation
=========

This role will install or uninstall the CrowdStrike Falcon Sensor.

Requirements
------------

Ansible 2.10 or higher

Role Variables
--------------

Currently the following variables are supported:

### Falcon Installation

 * `falcon_cid` - Your Falcon Customer ID (CID) (string, default: null)
 * `falcon_provisioning_token` - Falcon Installation Token (string, default: null)
 * `falcon_install_method` - The installation method for installing the sensor (string, default: api)
 * `falcon_gpg_key` - Location of the Falcon GPG Key file (string, default: null)
 * `falcon_remove_agent_id` - Remote the Falcon Agent ID (AID) (bool, default: false)
 * `falcon_api_url` - CrowdStrike API URL for downloading the Falcon sensor (string, default: `api.crowdstrike.com`)
 * `falcon_api_client_id` - CrowdStrike OAUTH Client ID (string, default: null)
 * `falcon_api_client_secret` - CrowdStrike OAUTH Client Secret (string, default: null)
 * `falcon_install_tmp_dir` - Temporary download and installation directory for the Falson Sensor (string, default: null)
 * `falcon_download_url` - URL for downloading the sensor (string, default: null)
 * `falcon_retries` - Number of attempts to download the sensor (int, default: 3)
 * `falcon_delay` - Number of seconds before trying another download attempt (int, default: 3)
 * `falcon_uninstall` - Uninstall the Falcon Sensor (bool, default: false)

See [default/main.yaml](default/main.yaml) for more details on these variables.

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
  - role: falcon_installation
  vars:
    falcon_api_client_id: <Falcon_UI_OAUTH_client_id>
    falcon_api_client_secret: <Falcon_UI_OAUTH_client_secret>
```

This example uninstalls the Falcon Sensor:

```yaml
---
- hosts: all
  roles:
  - role: falcon_installation
  vars:
    falcon_uninstall: true
```

License
-------

[Unlicense](LICENSE)

Author Information
------------------

CrowdStrike Solutions Architects
