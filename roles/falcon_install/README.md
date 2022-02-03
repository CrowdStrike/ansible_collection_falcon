falcon_install
=========

This role will install the CrowdStrike Falcon Sensor.

Requirements
------------

Ansible 2.11 or higher

Role Variables
--------------

The following variables are currently supported:

 * `falcon_api_no_log` - Whether to enable or disable the logging of sensitive data being exposed in API calls. (bool, default: true)
 * `falcon_install_method` - The installation method for installing the sensor (string, default: api)
 * `falcon_gpg_key` - Location of the Falcon GPG Key file (string, default: null)
 * `falcon_cloud` - CrowdStrike API URL for downloading the Falcon sensor (string, default: `api.crowdstrike.com`)
 * `falcon_cloud_autodiscover` - Auto-discover CrowdStrike API Cloud region (bool, default: true)
 * `falcon_cid` - Manually specify CrowdStrike Customer ID for Windows installations (string, default: null)
 * `falcon_client_id` - CrowdStrike OAUTH Client ID (string, default: null)
 * `falcon_client_secret` - CrowdStrike OAUTH Client Secret (string, default: null)
 * `falcon_sensor_version_decrement` - Sensor N-x version to install (int, default: 0 [latest])
 * `falcon_sensor_update_policy_name` - Sensor update policy used to control sensor version (string, default: null)
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

See [default/main.yml](default/main.yml) for more details on these variables.

Dependencies
------------

- Privilege escalation (sudo) is required for this role to function properly.
- Make sure that scope Sensor Download [read] is enabled in the CrowdStrike API.
- To use `falcon_sensor_update_policy_name`, make sure that scope Sensor update policies [read] is enabled in the CrowdStrike API.

Example Playbooks
----------------

This example installs the latest Falcon Sensor:

```yaml
---
- hosts: all
  roles:
  - role: crowdstrike.falcon.falcon_install
    vars:
      falcon_client_id: <Falcon_UI_OAUTH_client_id>
      falcon_client_secret: <Falcon_UI_OAUTH_client_secret>
```
---
This example installs the Falcon Sensor at version N-2:
```yaml
---
- hosts: all
  roles:
  - role: crowdstrike.falcon.falcon_install
    vars:
      falcon_client_id: <Falcon_UI_OAUTH_client_id>
      falcon_client_secret: <Falcon_UI_OAUTH_client_secret>
      falcon_sensor_version_decrement: 2
```
---
This example installs the Falcon Sensor using a sensor update policy called "ACME Policy":
```yaml
---
- hosts: all
  roles:
  - role: crowdstrike.falcon.falcon_install
    vars:
      falcon_client_id: <Falcon_UI_OAUTH_client_id>
      falcon_client_secret: <Falcon_UI_OAUTH_client_secret>
      falcon_sensor_update_policy_name: "ACME Policy"
```
License
-------

[License](https://github.com/crowdstrike/ansible_collection_falcon/blob/main/LICENSE)

Author Information
------------------

CrowdStrike Solution Architects
