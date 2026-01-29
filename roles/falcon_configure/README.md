# crowdstrike.falcon.falcon_configure

Configures the CrowdStrike Falcon Sensor. This role is focused mainly on configuring the Falcon Sensor on Linux and macOS. Windows is supported, but not as much functionality is currently available. The main difference is because a lot of the configuration options can be set during the installation of the sensor on Windows.

> [!IMPORTANT]
> The Falcon Customer ID (CID) with checksum is ***required*** in order to properly configure and start the Falcon Sensor.
> You can either pass the CID as a variable (`falcon_cid`) or let this role fetch it from the CrowdStrike API using your
> API credentials.

## Requirements

- Ansible 2.13 or higher
- FalconPy 1.3.0 or higher on Ansible control node

> As of version 4.0.0, this role takes full advantage of the FalconPy SDK for interacting with the CrowdStrike API.

## Role Variables

### API Specific Variables

- `falcon_client_id` - CrowdStrike OAUTH Client ID (string, default: ***null***)
- `falcon_client_secret` - CrowdStrike OAUTH Client Secret (string, default: ***null***)
- `falcon_cloud` - CrowdStrike API URL for API operations (string, default: ***us-1***)
  - Controls API endpoint selection for authentication and data retrieval
  - Can be specified as either a cloud alias (us-1, us-2, etc.) or full URL
  - choices:
    - **us-1** -> api.crowdstrike.com
    - **us-2** -> api.us-2.crowdstrike.com
    - **us-gov-1** -> api.laggar.gcw.crowdstrike.com
    - **eu-1** -> api.eu-1.crowdstrike.com
- `falcon_api_enable_no_log` - Whether to enable or disable the logging of sensitive data being exposed in API calls (bool, default: ***true***)

### Sensor Configuration Variables

- `falcon_sensor_cloud` - Cloud region for the Falcon sensor to connect to (string, default: ***null***)
  - Specifies which CrowdStrike cloud region the sensor should connect to
  - Only available for sensor version 7.28.0 and above with unified installer support
  - Helps resolve AID generation timeouts by connecting to the correct cloud endpoint immediately
  - Independent of API cloud configuration (falcon_cloud)
  - Valid values: `us-1`, `us-2`, `eu-1`, `us-gov-1`, `us-gov-2`

### Common Variables

- `falcon_remove_aid` - Remove the Falcon Agent ID (AID) (bool, default: ***null***)

### Linux Specific Variables

- `falcon_aid_retries` - Number of retries to attempt when waiting to retrieve the Falcon Agent ID (AID) (int, default: ***12***)
- `falcon_aid_delay` - Number of seconds to wait between `falcon_aid_retries` when waiting to retrieve the Falcon Agent ID (AID) (int, default: ***10***)

> [!NOTE]
> These variables control the retry behavior when attempting to retrieve the Falcon Agent ID (AID) after configuring
> and restarting the sensor. The default values should work for most, but you may need to increase them in
> environments with slower startup times.

> [!IMPORTANT]
> For sensor version 7.28+, specifying the correct `falcon_sensor_cloud`
> region can significantly reduce AID generation time by connecting to the proper cloud endpoint immediately.

### Windows Specific Variables

- `falcon_windows_become` - Whether to become a privileged user on Windows (bool, default: ***true***)
- `falcon_windows_become_method` - The way to become a privileged user on Windows (string, default: ***runas***)
- `falcon_windows_become_user` - The privileged user to install the sensor on Windows (string, default: ***SYSTEM***)
- `falcon_tags` - Sensor grouping tags (string, default: ***null***)
  - Requires sensor version 6.42+ (uses `CsSensorSettings.exe` utility)
  - See [Grouping Tags on Windows](#grouping-tags-on-windows) for details

### macOS Specific Variables

- `falcon_option_set` - Set True|yes to set options, False|no to delete. (bool, default: ***true***)
- `falcon_cid` - Your Falcon Customer ID (CID) if not using API creds (string, default: ***null***)
- `falcon_provisioning_token` - Falcon Installation Token (string, default: ***null***)
- `falcon_tags` - Sensor grouping tags are optional, user-defined identifiers you can use to group and filter hosts (string, default: ***null***)

### Falconctl Variables (Linux Only)

> This role uses the [crowdstrike.falcon.falconctl](https://github.com/CrowdStrike/ansible_collection_falcon/blob/main/plugins/modules/falconctl.py) Ansible Module to configure the Falcon Sensor on Linux.

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

## Grouping Tags on Windows

Starting with sensor version 6.42+, Windows supports post-installation grouping tag management using the `CsSensorSettings.exe` utility.

### Methods for Setting Grouping Tags on Windows

1. **During Installation** (via `falcon_install` role):
   ```yaml
   falcon_windows_install_args: "/norestart GROUPING_TAGS=tag1,tag2"
   ```

2. **Post-Installation** (via `falcon_configure` role):
   ```yaml
   falcon_tags: "tag1,tag2"
   ```

### Behavior Notes

- The `falcon_configure` role checks current tags before making changes (idempotent)
- If `falcon_tags` matches existing tags, no changes are made
- Setting `falcon_option_set: false` with `falcon_tags` defined will clear existing tags

### Mixed Environment Considerations

> [!IMPORTANT]
> If you use a top-level `falcon_tags` variable in a mixed Linux/macOS/Windows environment,
> Windows hosts will now be affected (sensor 6.42+). Previously, `falcon_tags` only applied
> to Linux and macOS.

To set different tags per OS, use inventory group variables:

```yaml
# group_vars/linux.yml
falcon_tags: "linux-servers,production"

# group_vars/windows.yml
falcon_tags: "windows-servers,production"
```

Or use conditionals in your playbook:

```yaml
- hosts: all
  roles:
  - role: crowdstrike.falcon.falcon_configure
    vars:
      falcon_tags: "{{ 'windows-tag' if ansible_os_family == 'Windows' else 'linux-tag' }}"
```

## Falcon API Permissions

API clients are granted one or more API scopes. Scopes allow access to specific CrowdStrike APIs and describe the actions that an API client can perform.

Ensure the following API scopes are enabled (***if applicable***) for this role:

- When using API credentials `falcon_client_id` and `falcon_client_secret`
  - **Sensor Download** [read]

## Dependencies

- Privilege escalation (sudo/runas) is required for this role to function properly.
  > See [Privilege Escalation Requirements](https://github.com/CrowdStrike/ansible_collection_falcon/blob/main/README.md#privilege-escalation-requirements) for more information.
- The Falcon Sensor must be installed on the target host
  > See the [falcon_install](https://github.com/CrowdStrike/ansible_collection_falcon/blob/main/roles/falcon_install/README.md) role to learn more about installing the Falcon sensor.

## Maintenance Token Best Practices

When working with protected Falcon sensors (versions 7.20+ for Linux), CrowdStrike recommends the following approaches:

### **Recommended: Sensor Update Policy Management**

The preferred method is to temporarily move hosts to a maintenance policy that has uninstall and maintenance protection disabled:

1. Create a sensor update policy for maintenance with:
   - Uninstall and maintenance protection **disabled**
   - Sensor version updates **off**
2. Move hosts to the maintenance policy before sensor operations
3. Perform configuration changes
4. Move hosts back to their original policies

### **Alternative: Bulk Maintenance Token**

When policy management isn't feasible, use bulk maintenance tokens:

> [!IMPORTANT]
> Bulk tokens work across multiple hosts and are more efficient than host-specific tokens. Ensure bulk maintenance tokens are enabled in your CrowdStrike environment.

Using the lookup plugin via API:

```yaml
---
- hosts: all
  vars:
    falcon_client_id: <FALCON_CLIENT_ID>
    falcon_client_secret: <FALCON_CLIENT_SECRET>
  roles:
  - role: crowdstrike.falcon.falcon_configure
    vars:
      falcon_maintenance_token: "{{ lookup('crowdstrike.falcon.maintenance_token',
                                          bulk=true,
                                          client_id=falcon_client_id,
                                          client_secret=falcon_client_secret) }}"
```

Alternatively you can provide a pre-obtained token:

```yaml
---
- hosts: all
  roles:
  - role: crowdstrike.falcon.falcon_configure
    vars:
      falcon_maintenance_token: "your-maintenance-token-here"
```

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

How to configure for specific cloud regions (sensor v7.28+):

```yaml
# API-based workflow with explicit sensor cloud region
- hosts: all
  roles:
  - role: crowdstrike.falcon.falcon_configure
    vars:
      falcon_client_id: <FALCON_CLIENT_ID>
      falcon_client_secret: <FALCON_CLIENT_SECRET>
      falcon_sensor_cloud: us-2  # Explicit sensor cloud region
      # falcon_cloud can autodiscover any region for API operations

# Non-API workflow with sensor cloud region
- hosts: all
  roles:
  - role: crowdstrike.falcon.falcon_configure
    vars:
      falcon_cid: 1234567890ABCDEF1234567890ABCDEF-12
      falcon_sensor_cloud: us-2  # No dependency on API configuration
```

> **Note**: For Falcon sensor v7.28+ with unified installers, specifying `falcon_sensor_cloud`
> helps prevent AID generation timeouts by ensuring the sensor connects to the proper cloud endpoint immediately
> instead of trying multiple regions sequentially.

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
