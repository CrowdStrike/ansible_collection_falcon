[![Galaxy version](https://img.shields.io/badge/dynamic/json?style=flat&label=galaxy&prefix=v&url=https://galaxy.ansible.com/api/v2/collections/crowdstrike/falcon/&query=latest_version.version)](https://galaxy.ansible.com/CrowdStrike/falcon)
[![Ansible Lint](https://github.com/CrowdStrike/ansible_collection_falcon/actions/workflows/ansible-lint.yml/badge.svg)](https://github.com/CrowdStrike/ansible_collection_falcon/actions/workflows/ansible-lint.yml)
[![Ansible Test](https://github.com/CrowdStrike/ansible_collection_falcon/actions/workflows/ansible-test.yml/badge.svg)](https://github.com/CrowdStrike/ansible_collection_falcon/actions/workflows/ansible-test.yml)
[![YAML Lint](https://github.com/CrowdStrike/ansible_collection_falcon/actions/workflows/yamllint.yml/badge.svg)](https://github.com/CrowdStrike/ansible_collection_falcon/actions/workflows/yamllint.yml)
[![Python Lint](https://github.com/CrowdStrike/ansible_collection_falcon/actions/workflows/linting.yml/badge.svg)](https://github.com/CrowdStrike/ansible_collection_falcon/actions/workflows/linting.yml)

# Ansible Collection - crowdstrike.falcon

This collection is focused on installing, configuring, and removing CrowdStrike's Falcon sensor on macOS, Linux, and Windows.

## Ansible version compatibility
This collection has been tested against and supports the following Ansible versions: **>=2.11**

## Included content
### Roles

| Role Name | Documentation | Linux Status | Windows Status |
| --------- | :-----------: | ------------ | -------------- |
| crowdstrike.falcon.falcon_install | [Readme](https://github.com/CrowdStrike/ansible_collection_falcon/blob/main/roles/falcon_install/README.md) | ![GitHub Workflow Status](https://img.shields.io/github/workflow/status/CrowdStrike/ansible_collection_falcon/crowdstrike.falcon.falcon_install) | ![GitHub Workflow Status](https://img.shields.io/github/workflow/status/CrowdStrike/ansible_collection_falcon/(Windows)%20crowdstrike.falcon.falcon_install)
| crowdstrike.falcon.falcon_configure | [Readme](https://github.com/CrowdStrike/ansible_collection_falcon/blob/main/roles/falcon_configure/README.md) | ![GitHub Workflow Status](https://img.shields.io/github/workflow/status/CrowdStrike/ansible_collection_falcon/crowdstrike.falcon.falcon_configure) | ![GitHub Workflow Status](https://img.shields.io/github/workflow/status/CrowdStrike/ansible_collection_falcon/(Windows)%20crowdstrike.falcon.falcon_configure)
| crowdstrike.falcon.falcon_uninstall | [Readme](https://github.com/CrowdStrike/ansible_collection_falcon/blob/main/roles/falcon_uninstall/README.md) | ![GitHub Workflow Status](https://img.shields.io/github/workflow/status/CrowdStrike/ansible_collection_falcon/crowdstrike.falcon.falcon_uninstall) | ![GitHub Workflow Status](https://img.shields.io/github/workflow/status/CrowdStrike/ansible_collection_falcon/(Windows)%20crowdstrike.falcon.falcon_uninstall)

## Using this collection
Before using the collection, you need to install the collection with the `ansible-galaxy` CLI:

```bash
ansible-galaxy collection install crowdstrike.falcon
```

You can also include it in a `requirements.yml` file and install it via `ansible-galaxy collection install -r requirements.yml` using the format:

```yaml
collections:
  - crowdstrike.falcon
```

**Note** that if you install the collection from Ansible Galaxy, it will not be upgraded automatically when you upgrade the `ansible` package. To upgrade the collection to the latest available version, run the following command:
```bash
ansible-galaxy collection install crowdstrike.falcon --upgrade
```

You can also install a specific version of the collection, for example, if you need to downgrade when something is broken in the latest version (please report an issue in this repository). Use the following syntax to install version `0.1.0`:

```bash
ansible-galaxy collection install crowdstrike.falcon:==0.1.0
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
