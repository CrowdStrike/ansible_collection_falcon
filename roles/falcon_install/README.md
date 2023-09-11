# crowdstrike.falcon.falcon_install

This role installs the CrowdStrike Falcon Sensor. This role also supports installing
the sensor from a local file or remote URL.

## Requirements

- Ansible 2.12 or higher

## Role Variables

The following variables are currently supported:

### Installation Method

- `falcon_install_method` - The installation method for installing the sensor (string, default: `api`)
  - choices:
    - `api` - Install the sensor using the CrowdStrike API
    - `file` - Install the sensor using a local file
    - `url` - Install the sensor using a remote URL

### Common Installation Variables

- `falcon_allow_downgrade` - Whether or not to allow downgrading the sensor version (bool, default: `false`)
- `falcon_gpg_key_check` - Whether or not to verify the Falcon sensor Linux based package (bool, default: `true`)
- `falcon_cid` - Specify CrowdStrike Customer ID with Checksum (string, default: `null`)
  - :warning: When `falcon_install_method` is set to **api**, this value will be fetched by the API unless specified.
- `falcon_install_tmp_dir` - Temporary Linux and MacOS installation directory for the Falson Sensor (string, default: `/tmp/`)
- `falcon_retries` - Number of attempts to download the sensor (int, default: `3`)
- `falcon_delay` - Number of seconds before trying another download attempt (int, default: `3`)

### API Installation Variables

- `falcon_client_id` - CrowdStrike OAUTH Client ID (string, default: `null`)
- `falcon_client_secret` - CrowdStrike OAUTH Client Secret (string, default: `null`)
- `falcon_cloud` - CrowdStrike API URL for downloading the Falcon sensor (string, default: `api.crowdstrike.com`)
- `falcon_cloud_autodiscover` - Auto-discover CrowdStrike API Cloud region (bool, default: `true`)
- `falcon_api_auth_run_once` - Whether to enable or disable the run_once option for API auth calls. (bool, default: `true`)
- `falcon_api_enable_no_log` - Whether to enable or disable the logging of sensitive data being exposed in API calls (bool, default: `true`)
- `falcon_api_sensor_download_path` - Local directory path to download the sensor to (string, default: `null`)
- `falcon_api_sensor_download_filename` - The name to save the sensor file as (string, default: `null`)
- `falcon_api_sensor_download_cleanup` - Whether or not to delete the downloaded sensor after transfer to remote host (bool, default: `true`)
- `falcon_sensor_version` - Sensor version to install (string, default: `null`)
- `falcon_sensor_version_decrement` - Sensor N-x version to install (int, default: 0 [latest])
- `falcon_sensor_update_policy_name` - Sensor update policy used to control sensor version (string, default: `null`)

### File Installation Variables

- `falcon_localfile_path` - Absolute path to local falcon sensor package (string, default: `null`)
- `falcon_localfile_cleanup` - Allow removing the local file after install (bool, default: `false`)

### URL Installation Variables

- `falcon_download_url` - URL for downloading the sensor (string, default: `null`)
- `falcon_download_url_username` - username for downloading the sensor (string, default: `null`)
- `falcon_download_url_password` - password for downloading the sensor (string, default: `null`)

### Windows Specific Variables

- `falcon_windows_install_retries` - Number of times to retry sensor install on windows (int, default: `10`)
- `falcon_windows_install_delay` - Number of seconds to wait to retry sensor install on windows in the event of a failure (int, default: `120`)
- `falcon_windows_tmp_dir` - Temporary Windows installation directory for the Falson Sensor (string, default: `%SYSTEMROOT%\\Temp`)
- `falcon_windows_install_args` - Additional Windows install arguments (string, default: `/norestart`)
- `falcon_windows_uninstall_args` - Additional Windows uninstall arguments (string, default: `/norestart`)
- `falcon_windows_become_method` - The way to become a privileged user on Windows (string, default: `runas`)
- `falcon_windows_become_user` - The privileged user to install the sensor on Windows (string, default: `SYSTEM`)

See [defaults/main.yml](defaults/main.yml) for more details on these variables.

## Falcon API Permissions

API clients are granted one or more API scopes. Scopes allow access to specific CrowdStrike APIs and describe the actions that an API client can perform.

Ensure the following API scopes are enabled (***if applicable***) for this role:

- When `falcon_install_method` is set to **api** (default)
  - **Sensor Download** [read]
  - **Sensor update policies** [read]
- When `falcon_sensor_update_policy_name` is used
  - **Sensor update policies** [read]

## Dependencies

- Privilege escalation is required for this role to function properly.

## Example Playbooks

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

----------

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

----------

This example installs the Falcon Sensor at version 6.40.13707:

```yaml
---
- hosts: all
  roles:
  - role: crowdstrike.falcon.falcon_install
    vars:
      falcon_client_id: <Falcon_UI_OAUTH_client_id>
      falcon_client_secret: <Falcon_UI_OAUTH_client_secret>
      falcon_sensor_version: '6.40.13707'
```

----------

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

This example installs the Falcon Sensor from a local file, then removes it.

```yaml
---
- hosts: all
  roles:
  - role: crowdstrike.falcon.falcon_install
    vars:
      falcon_install_method: file
      falcon_localfile_path: /tmp/falcon.deb
      falcon_localfile_cleanup: yes
      falcon_cid: <FALCON CID with Checksum>
```

## License

[License](https://github.com/crowdstrike/ansible_collection_falcon/blob/main/LICENSE)

## Author Information

CrowdStrike Solution Architects
