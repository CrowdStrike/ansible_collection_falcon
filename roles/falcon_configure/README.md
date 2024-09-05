# crowdstrike.falcon.falcon_configure

This role configures the CrowdStrike Falcon Sensor. For Linux and macOS, this role requires the Falcon
sensor to be installed prior to running this role.

> [!NOTE]
> This role is focused mainly on configuring the Falcon Sensor on Linux and MacOS. Windows is supported, but not as
> much functionality is currently available. The main difference is because a lot of the configuration options can
> be set during the installation of the sensor on Windows. We do plan to add more functionality to this role in the
> future.

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

### Common Variables

- `falcon_remove_aid` - Remove the Falcon Agent ID (AID) (bool, default: ***null***)

### Windows Specific Variables

- `falcon_windows_become` - Whether to become a privileged user on Windows (bool, default: ***true***)
- `falcon_windows_become_method` - The way to become a privileged user on Windows (string, default: ***runas***)
- `falcon_windows_become_user` - The privileged user to install the sensor on Windows (string, default: ***SYSTEM***)

### macOS Specific Variables

- `falcon_option_set` - Set True|yes to set options, False|no to delete. (bool, default: ***true***)
- `falcon_cid` - Your Falcon Customer ID (CID) if not using API creds (string, default: ***null***)
- `falcon_provisioning_token` - Falcon Installation Token (string, default: ***null***)
- `falcon_tags` - Sensor grouping tags are optional, user-defined identifiers you can use to group and filter hosts (string, default: ***null***)

### Falconctl Variables (Linux Only)

> This role uses the [crowdstrike.falcon.falconctl](../../plugins/modules/falconctl.py) Ansible Module to configure the Falcon Sensor on Linux.

- `falcon_option_set` - Set True|yes to set options, False|no to delete. *See note below (bool, default: ***true***)
- `falcon_cid` - Your Falcon Customer ID (CID) if not using API creds (string, default: ***null***)
- `falcon_provisioning_token` - Falcon Installation Token (string, default: ***null***)
- `falcon_apd` - Enable/Disable the Falcon Proxy (string, default: ***null***)
  > To enable proxy, set as: ***false***
- `falcon_aph` - Falcon Proxy host (by FQDN or IP) (string, default: ***null***)
- `falcon_app` - Falcon Proxy port (string, default: ***null***)
- `falcon_trace` - Configure additional traces for debugging (string, default: ***null***)
- `falcon_feature` - Configures additional features to the sensor (list, default: ***null***)
- `falcon_message_log` - Enable/Disable message logs (string, default: ***null***)
- `falcon_billing` - Configure Falcon sensor with Pay-As-You-Go billing (string, default: ***null***)
- `falcon_tags` - Sensor grouping tags are optional, user-defined identifiers you can use to group and filter hosts (string, default: ***null***)
- `falcon_backend` - The backend to use for the Falcon Sensor `[auto|bpf|kernel]` (string, default: ***null***)

----------

> :warning: **Warning:** **_Not all options can be set and deleted._**
>
> View the table below for a full list of options along with their respected states:

| Option                    | State |
|---------------------------|-------|
| falcon_cid                | S/D   |
| falcon_provisioning_token | S/D   |
| falcon_remove_aid         | D     |
| falcon_apd                | S/D   |
| falcon_aph                | S/D   |
| falcon_app                | S/D   |
| falcon_trace              | S/D   |
| falcon_feature            | S     |
| falcon_message_log        | S     |
| falcon_billing            | S/D   |
| falcon_tags               | S/D   |
| falcon_backend            | S/D   |

## Configuring on macOS

Apple platforms require Mobile Device Management (MDM) software to install kernel extensions without user prompting.
Ansible is only able to run on macOS in an interactive session, which means end-users will receive prompts to accept the CrowdStrike kernel modules without an MDM profile already established.

## Falcon API Permissions

API clients are granted one or more API scopes. Scopes allow access to specific CrowdStrike APIs and describe the actions that an API client can perform.

Ensure the following API scopes are enabled (***if applicable***) for this role:

- When using API credentials `falcon_client_id` and `falcon_client_secret`
  - **Sensor Download** [read]

## Dependencies

- Privilege escalation (sudo) is required for this role to function properly.
- Falcon Sensor must be installed

## Example Playbooks

How to set the Falcon Customer ID (CID) when CID is known:

```yaml
- hosts: all
  roles:
  - role: crowdstrike.falcon.falcon_configure
    vars:
      falcon_cid: 1234567890ABCDEF1234567890ABCDEF-12
```

----------

How to set the Falcon Customer ID (CID) using API creds:

```yaml
- hosts: all
  roles:
  - role: crowdstrike.falcon.falcon_configure
    vars:
      falcon_client_id: <FALCON_CLIENT_ID>
      falcon_client_secret: <FALCON_CLIENT_SECRET>
```

----------

How to set the Falcon Customer ID (CID) w/ provisioning token:

```yaml
- hosts: all
  roles:
  - role: crowdstrike.falcon.falcon_configure
    vars:
      falcon_cid: 1234567890ABCDEF1234567890ABCDEF-12
      falcon_provisioning_token: 12345678
```

----------

How to configure the Falcon Sensor Proxy:

```yaml
- hosts: all
  roles:
  - role: crowdstrike.falcon.falcon_configure
    vars:
      falcon_apd: no
      falcon_aph: 'example.com'
      falcon_app: 8080
```

----------

This example shows how to set some of the other options:

```yaml
- hosts: all
  roles:
  - role: crowdstrike.falcon.falcon_configure
    vars:
      falcon_tags: 'falcon,example,tags'
      falcon_billing: 'metered'
      falcon_message_log: yes
```

----------

Examples of deleting options:

```yaml
- hosts: all
  roles:
  - role: crowdstrike.falcon.falcon_configure
    vars:
      falcon_option_set: no
      falcon_cid: ""
      falcon_tags: ""
```

----------

Delete Agent ID to prep Master Image/Gold Image:

```yaml
- hosts: all
  roles:
  - role: crowdstrike.falcon.falcon_configure
    vars:
      falcon_option_set: yes
      falcon_cid: 1234567890ABCDEF1234567890ABCDEF-12
      falcon_remove_aid: yes
```

----------

Delete Agent ID as standalone task:

```yaml
- hosts: all
  roles:
  - role: crowdstrike.falcon.falcon_configure
    vars:
      falcon_remove_aid: yes
```

## License

[License](https://github.com/crowdstrike/ansible_collection_falcon/blob/main/LICENSE)

## Author Information

CrowdStrike Solution Architects
