# crowdstrike.falcon.falcon_uninstall

Uninstalls the CrowdStrike Falcon Sensor.

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
   > :warning:
   > Please use `Host Retention Policies` under `Host Management` in the Falcon console which provides more flexibility and customization for automatically hiding and deleting hosts instead.

### Maintenance Token Variables

- `falcon_maintenance_token` - Maintenance token for sensor operations when uninstall and maintenance protection is enabled (string, default: ***null***)
  > Required for sensor versions 7.20+ when protection is armed. Can be retrieved using the maintenance_token lookup plugin or provided manually.

### Windows Specific Variables

- `falcon_windows_uninstall_args` - Additional Windows uninstall arguments (string, default: ***/norestart***)
- `falcon_windows_become` - Whether to become a privileged user on Windows (bool, default: ***true***)
- `falcon_windows_become_method` - The way to become a privileged user on Windows (string, default: ***runas***)
- `falcon_windows_become_user` - The privileged user to uninstall the sensor on Windows (string, default: ***SYSTEM***)

See [defaults/main.yml](https://github.com/CrowdStrike/ansible_collection_falcon/blob/main/roles/falcon_uninstall/defaults/main.yml) for more details on these variables.

## Falcon API Permissions

API clients are granted one or more API scopes. Scopes allow access to specific CrowdStrike APIs and describe the actions that an API client can perform.

Ensure the following API scopes are enabled (**if applicable**) for this role:

- When using API credentials `falcon_client_id` and `falcon_client_secret`
  - To hide/remove the host from the CrowdStrike console:
    - **Host** [write]
  - To retrieve maintenance tokens using the lookup plugin:
    - **Sensor update policies** [write]

## Dependencies

- Privilege escalation (sudo/runas) is required for this role to function properly.
  > See [Privilege Escalation Requirements](https://github.com/CrowdStrike/ansible_collection_falcon/blob/main/README.md#privilege-escalation-requirements) for more information.

## Maintenance Token Best Practices

When working with protected Falcon sensors (versions 7.20+ for Linux), CrowdStrike recommends the following approaches:

### **Recommended: Sensor Update Policy Management**

The preferred method is to temporarily move hosts to a maintenance policy that has uninstall and maintenance protection disabled:

1. Create a sensor update policy for maintenance with:
   - Uninstall and maintenance protection **disabled**
   - Sensor version updates **off**
2. Move hosts to the maintenance policy before sensor operations
3. Perform sensor upgrade/downgrade/reinstall
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
  - role: crowdstrike.falcon.falcon_uninstall
    vars:
      falcon_remove_host: true
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
  - role: crowdstrike.falcon.falcon_uninstall
    vars:
      falcon_maintenance_token: "your-maintenance-token-here"
```

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

Use a single bulk token for all hosts in your environment:

> Requires bulk token to be enabled in your policy.

```yaml
---
- hosts: all
  vars:
    falcon_client_id: <FALCON_CLIENT_ID>
    falcon_client_secret: <FALCON_CLIENT_SECRET>
  roles:
  - role: crowdstrike.falcon.falcon_uninstall
    vars:
      falcon_maintenance_token: "{{ lookup('crowdstrike.falcon.maintenance_token',
                                          bulk=true,
                                          client_id=falcon_client_id,
                                          client_secret=falcon_client_secret) }}"
```

### Troubleshooting

- If uninstall fails, the sensor likely has protection enabled and requires a maintenance token
- Bulk tokens work for most scenarios and are the recommended approach
- Host-specific tokens require the sensor to be running and configured (AID available)
- Ensure **Sensor update policies** [write] API scope is enabled for token retrieval

## License

[License](https://github.com/crowdstrike/ansible_collection_falcon/blob/main/LICENSE)

## Author Information

CrowdStrike Solution Architects
