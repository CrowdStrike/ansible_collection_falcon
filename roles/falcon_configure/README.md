falcon_configure
=========

This role will configure the CrowdStrike Falcon Sensor.

Requirements
------------

Ansible 2.10 or higher

Role Variables
--------------

 * `falcon_option_set` - Set True|yes to set options, False|no to delete. *See note below (bool, default: true)
 * `falcon_cid` - Your Falcon Customer ID (CID) (string, default: null)
 * `falcon_provisioning_token` - Falcon Installation Token (string, default: null)
 * `falcon_remove_aid` - Remove the Falcon Agent ID (AID) (bool, default: null)
 * `falcon_apd` - Whether to enable or disable the Falcon sensor to use a proxy (bool, default: null)
 * `falcon_aph` - Falcon Proxy host (by FQDN or IP) (string, default: null)
 * `falcon_app` - Falcon Proxy port (int, default: null)
 * `falcon_trace` - Configure additional traces for debugging (string, default: null)
 * `falcon_feature` - Configures additional features to the sensor (string, default: null)
 * `falcon_metadata_query` - Enables additional sensor support in cloud environments (string, default: null)
 * `falcon_message_log` - Enables|Disables message logs (bool, default: null)
 * `falcon_billing` - Configure Falcon sensor with Pay-As-You-Go billing (string, default: null)
 * `falcon_tags` - Sensor grouping tags are optional, user-defined identifiers you can use to group and filter hosts (string, default: null)
 * `falcon_windows_become_method` - The way to become a privileged user on Windows (string, default: `runas`)
 * `falcon_windows_become_user` - The privileged user to install the sensor on Windows (string, default: `SYSTEM`)

***NOTE:** Not all options can be set and deleted. View the table below for a full list of options along with their respected states:

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
| falcon_metadata_query     | S     |
| falcon_message_log        | S     |
| falcon_billing            | S/D   |
| falcon_tags               | S/D   |

Dependencies
------------

- Privilege escalation (sudo) is required for this role to function properly.

Example Playbook
----------------

How to set the Falcon Customer ID (CID):
```yaml
- hosts: all
  roles:
  - role: crowdstrike.falcon.falcon_configure
    vars:
      falcon_cid: 1234567890ABCDEF1234567890ABCDEF-12
```

How to set the Falcon Customer ID (CID) w/ provisioning token:
```yaml
- hosts: all
  roles:
  - role: crowdstrike.falcon.falcon_configure
    vars:
      falcon_cid: 1234567890ABCDEF1234567890ABCDEF-12
      falcon_provisioning_token: 12345678
```

How to configure the Falcon Sensor Proxy:
```yaml
- hosts: all
  roles:
  - role: crowdstrike.falcon.falcon_configure
    vars:
      falcon_apd: yes
      falcon_aph: 'http://example.com'
      falcon_app: 8080
```

This example shows how to set some of the other options:
```yaml
- hosts: all
  roles:
  - role: crowdstrike.falcon.falcon_configure
    vars:
      falcon_tags: 'falcon,example,tags'
      falcon_metadata_query: 'enableAWS,disableGCP'
      falcon_billing: 'metered'
      falcon_message_log: yes
```

Examples of deleting certain options:
```yaml
- hosts: all
  roles:
  - role: crowdstrike.falcon.falcon_configure
    vars:
      falcon_option_state: no
      falcon_remove_aid: yes
      falcon_cid: ""
      falcon_tags: ""
```

Delete Agent ID to prep Master Image:
```yaml
- hosts: all
  roles:
  - role: crowdstrike.falcon.falcon_configure
    vars:
      falcon_option_state: no
      falcon_remove_aid: yes
```

License
-------

[License](https://github.com/crowdstrike/ansible_collection_falcon/blob/main/LICENSE)

Author Information
------------------

CrowdStrike Solution Architects
