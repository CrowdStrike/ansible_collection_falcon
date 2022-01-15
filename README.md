[![Galaxy version](https://img.shields.io/badge/dynamic/json?style=flat&label=galaxy&prefix=v&url=https://galaxy.ansible.com/api/v2/collections/crowdstrike/falcon/&query=latest_version.version)](https://galaxy.ansible.com/CrowdStrike/falcon)
[![Ansible Lint](https://github.com/CrowdStrike/ansible_collection_falcon/actions/workflows/ansible-lint.yml/badge.svg)](https://github.com/CrowdStrike/ansible_collection_falcon/actions/workflows/ansible-lint.yml)
[![Ansible Test](https://github.com/CrowdStrike/ansible_collection_falcon/actions/workflows/ansible-test.yml/badge.svg)](https://github.com/CrowdStrike/ansible_collection_falcon/actions/workflows/ansible-test.yml)
[![YAML Lint](https://github.com/CrowdStrike/ansible_collection_falcon/actions/workflows/yamllint.yml/badge.svg)](https://github.com/CrowdStrike/ansible_collection_falcon/actions/workflows/yamllint.yml)
[![Python Lint](https://github.com/CrowdStrike/ansible_collection_falcon/actions/workflows/linting.yml/badge.svg)](https://github.com/CrowdStrike/ansible_collection_falcon/actions/workflows/linting.yml)

# Ansible Collection - crowdstrike.falcon

This collection is focused on downloading, installing, and removing CrowdStrike's Falcon sensor on macOS, Linux, and Windows.

## Included content
### Roles

| Role Name | Documentation |
| --------- | :-----------: |
| crowdstrike.falcon.falcon_install | [Readme](https://github.com/CrowdStrike/ansible_collection_falcon/blob/main/roles/falcon_install/README.md) |
| crowdstrike.falcon.falcon_configure | [Readme](https://github.com/CrowdStrike/ansible_collection_falcon/blob/main/roles/falcon_configure/README.md) |
| crowdstrike.falcon.falcon_uninstall | [Readme](https://github.com/CrowdStrike/ansible_collection_falcon/blob/main/roles/falcon_uninstall/README.md) |


## Using this collection
Before using the collection, you need to install the collection with the `ansible-galaxy` CLI:

```
ansible-galaxy collection install crowdstrike.falcon
```

You can also include it in a `requirements.yml` file and install it via `ansible-galaxy collection install -r requirements.yml` using the format:

```yaml
collections:
  - crowdstrike.falcon
```

#### Example Playbook
Install and configure the CrowdStrike Falcon Sensor at version N-2:
```yaml
- hosts: all
  vars:
    falcon_client_id: <Falcon_UI_OAUTH_client_id>
    falcon_client_secret: <Falcon_UI_OAUTH_client_secret>
  roles:
  - role: crowdstrike.falcon.falcon_install
    vars:
      falcon_sensor_version_decrement: 2
  - role: crowdstrike.falcon.falcon_configure
    vars:
      # falcon_cid is autodetected using falcon_client_id|secret vars
      falcon_tags: 'falcon,example,tags'
```

## Installing on MacOS

Apple platforms require Mobile Device Management (MDM) software to install kernel extensions without user prompting.
Ansible is only able to run on macOS in an interactive session, which means end-users will receive prompts to accept the CrowdStrike kernel modules.


## More information on Ansible and Ansible Collections
- [Ansible Collection Overview](https://github.com/ansible-collections/overview)
- [Ansible Using Collections](https://docs.ansible.com/ansible/latest/user_guide/collections_using.html)
- [Ansible User Guide](https://docs.ansible.com/ansible/latest/user_guide/index.html)


## Contributing
If you want to develop new content or improve on this collection, please open an issue or create a pull request.
All contributions are welcome!


# License

See the [license](LICENSE) for more information.
