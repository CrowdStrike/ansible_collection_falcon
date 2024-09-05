# crowdstrike.falcon.falcon_uninstall

This role uninstalls the CrowdStrike Falcon Sensor.

## Requirements

- Ansible 2.13 or higher
- FalconPy 1.3.0 or higher on Ansible control node

> As of version 4.0.0, this role takes full advantage of the FalconPy SDK for interacting with the CrowdStrike API.

## Role Variables

### API Specific Variables

- `falcon_client_id` - CrowdStrike OAUTH Client ID (string, default: ***null***)
- `falcon_client_secret` - CrowdStrike OAUTH Client Secret (string, default: ***null***)
- `falcon_cloud` - CrowdStrike API URL for downloading the Falcon sensor (string, default: ***us-1***)
  - choices:
    - **us-1** -> api.crowdstrike.com
    - **us-2** -> api.us-2.crowdstrike.com
    - **us-gov-1** -> api.laggar.gcw.crowdstrike.com
    - **eu-1** -> api.eu-1.crowdstrike.com
- `falcon_api_enable_no_log` - Whether to enable or disable the logging of sensitive data being exposed in API calls (bool, default: ***true***)
- `falcon_remove_host` - Whether to hide/remove the host from the CrowdStrike console (bool, default: false)

### Windows Specific Variables

- `falcon_windows_uninstall_args` - Additional Windows uninstall arguments (string, default: ***/norestart***)
- `falcon_windows_become` - Whether to become a privileged user on Windows (bool, default: ***true***)
- `falcon_windows_become_method` - The way to become a privileged user on Windows (string, default: ***runas***)
- `falcon_windows_become_user` - The privileged user to uninstall the sensor on Windows (string, default: ***SYSTEM***)

See [defaults/main.yml](defaults/main.yml) for more details on these variables.

## Falcon API Permissions

API clients are granted one or more API scopes. Scopes allow access to specific CrowdStrike APIs and describe the actions that an API client can perform.

Ensure the following API scopes are enabled (**if applicable**) for this role:

- When using API credentials `falcon_client_id` and `falcon_client_secret`
  - To hide/remove the host from the CrowdStrike console:
    - **Host** [write]

## Dependencies

Privilege escalation (sudo) is required for this role to function properly.

## Example Playbooks

This example uninstalls the Falcon Sensor:

```yaml
---
- hosts: all
  roles:
  - role: crowdstrike.falcon.falcon_uninstall
```

This example uninstalls the Falcon Sensor and hides/removes the host from the CrowdStrike console:

```yaml
---
- hosts: all
  roles:
  - role: crowdstrike.falcon.falcon_uninstall
    vars:
      falcon_client_id: <FALCON_CLIENT_ID>
      falcon_client_secret: <FALCON_CLIENT_SECRET>
      falcon_cloud: us-2
      falcon_remove_host: true
```

This example uses a maintenance token to uninstall a Falcon Sensor on Windows:

```yaml
---
- hosts: all
  roles:
  - role: crowdstrike.falcon.falcon_uninstall
    vars:
      falcon_windows_uninstall_args: "/norestart MAINTENANCE_TOKEN=<Falcon_Maintenance_Token>"
```

## License

[License](https://github.com/crowdstrike/ansible_collection_falcon/blob/main/LICENSE)

## Author Information

CrowdStrike Solution Architects
