Uninstall
=========

This role uninstalls the CrowdStrike Falcon Sensor.

Requirements
------------

Ansible 2.11 or higher

Role Variables
--------------

The following variables are currently supported:

 * `falcon_api_enable_no_log` - Whether to enable or disable the logging of sensitive data being exposed in API calls. (bool, default: true)
 * `falcon_cloud` - CrowdStrike API URL for downloading the Falcon sensor (string, default: `api.crowdstrike.com`)
 * `falcon_cloud_autodiscover` - Auto-discover CrowdStrike API Cloud region (bool, default: true)
 * `falcon_client_id` - CrowdStrike API OAUTH Client ID (string, default: null)
 * `falcon_client_secret` - CrowdStrike API OAUTH Client Secret (string, default: null)
 * `falcon_remove_host` - Whether to hide/remove the host from the CrowdStrike console (bool, default: false)
 * `falcon_windows_uninstall_args` - Additional Windows uninstall arguments (string, default: `/norestart`)
 * `falcon_windows_become_method` - The way to become a privileged user on Windows (string, default: `runas`)
 * `falcon_windows_become_user` - The privileged user to uninstall the sensor on Windows (string, default: `SYSTEM`)

See [defaults/main.yml](defaults/main.yml) for more details on these variables.

Falcon API Permissions
----------------------

API clients are granted one or more API scopes. Scopes allow access to specific CrowdStrike APIs and describe the actions that an API client can perform.

Ensure the following API scopes are enabled (***if applicable***) for this role:

* When using API credentials `falcon_client_id` and `falcon_client_secret`
  * To hide/remove the host from the CrowdStrike console:
    * **Host** [write]****

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
