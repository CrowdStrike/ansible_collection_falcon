[![Galaxy version](https://img.shields.io/badge/dynamic/json?style=flat&label=galaxy&prefix=v&url=https://galaxy.ansible.com/api/v2/collections/crowdstrike/falcon/&query=latest_version.version)](https://galaxy.ansible.com/CrowdStrike/falcon)
[![Ansible Lint](https://github.com/CrowdStrike/ansible_collection_falcon/actions/workflows/ansible-lint.yml/badge.svg)](https://github.com/CrowdStrike/ansible_collection_falcon/actions/workflows/ansible-lint.yml)
[![Ansible Test](https://github.com/CrowdStrike/ansible_collection_falcon/actions/workflows/ansible-test.yml/badge.svg)](https://github.com/CrowdStrike/ansible_collection_falcon/actions/workflows/ansible-test.yml)
[![YAML Lint](https://github.com/CrowdStrike/ansible_collection_falcon/actions/workflows/yamllint.yml/badge.svg)](https://github.com/CrowdStrike/ansible_collection_falcon/actions/workflows/yamllint.yml)
[![Python Lint](https://github.com/CrowdStrike/ansible_collection_falcon/actions/workflows/linting.yml/badge.svg)](https://github.com/CrowdStrike/ansible_collection_falcon/actions/workflows/linting.yml)

# Ansible Collection - crowdstrike.falcon

This collection is focused on installing, configuring, and removing CrowdStrike's Falcon sensor on macOS, Linux, and Windows.

<!--start requires_ansible-->
## Ansible version compatibility

Tested with the Ansible Core >= 2.12.0 versions, and the current development version of Ansible. Ansible Core versions before 2.12.0 are not supported.
<!--end requires_ansible-->

## Included content

### Roles

> Please read each role's README to familiarize yourself with the role variables and other requirements.

| Role Name | Documentation | Build Status Linux | Build Status Windows |
| --------- | :-----------: | ------------------ | -------------------- |
| crowdstrike.falcon.falcon_install | [README](https://github.com/CrowdStrike/ansible_collection_falcon/blob/main/roles/falcon_install/README.md) | [![falcon_install](https://github.com/CrowdStrike/ansible_collection_falcon/actions/workflows/falcon_install.yml/badge.svg)](https://github.com/CrowdStrike/ansible_collection_falcon/actions/workflows/falcon_install.yml) | [![falcon_install](https://github.com/CrowdStrike/ansible_collection_falcon/actions/workflows/win_falcon_install.yml/badge.svg)](https://github.com/CrowdStrike/ansible_collection_falcon/actions/workflows/win_falcon_install.yml)
| crowdstrike.falcon.falcon_configure | [README](https://github.com/CrowdStrike/ansible_collection_falcon/blob/main/roles/falcon_configure/README.md) | [![falcon_configure](https://github.com/CrowdStrike/ansible_collection_falcon/actions/workflows/falcon_configure.yml/badge.svg)](https://github.com/CrowdStrike/ansible_collection_falcon/actions/workflows/falcon_configure.yml) | [![falcon_configure](https://github.com/CrowdStrike/ansible_collection_falcon/actions/workflows/win_falcon_configure.yml/badge.svg)](https://github.com/CrowdStrike/ansible_collection_falcon/actions/workflows/win_falcon_configure.yml)
| crowdstrike.falcon.falcon_uninstall | [README](https://github.com/CrowdStrike/ansible_collection_falcon/blob/main/roles/falcon_uninstall/README.md) | [![falcon_uninstall](https://github.com/CrowdStrike/ansible_collection_falcon/actions/workflows/falcon_uninstall.yml/badge.svg)](https://github.com/CrowdStrike/ansible_collection_falcon/actions/workflows/falcon_uninstall.yml) | [![falcon_uninstall](https://github.com/CrowdStrike/ansible_collection_falcon/actions/workflows/win_falcon_uninstall.yml/badge.svg)](https://github.com/CrowdStrike/ansible_collection_falcon/actions/workflows/win_falcon_uninstall.yml)

<!--start collection content-->
### Modules

Name | Description
--- | ---
[crowdstrike.falcon.falconctl](https://crowdstrike.github.io/ansible_collection_falcon/falconctl_module.html#ansible-collections-crowdstrike-falcon-falconctl-module)|Configure CrowdStrike Falcon Sensor
[crowdstrike.falcon.falconctl_info](https://crowdstrike.github.io/ansible_collection_falcon/falconctl_info_module.html#ansible-collections-crowdstrike-falcon-falconctl-info-module)|Get values associated with Falcon sensor.
[crowdstrike.falcon.sensor_policy_info](https://crowdstrike.github.io/ansible_collection_falcon/sensor_policy_info.html#ansible-collections-crowdstrike-falcon-sensor-policy-info-module)|Get information about Falcon Update Sensor Policies

<!--end collection content-->

<!--start eda content-->
### Event Sources

> Ansible EDA (Event Driven Ansible) is a new way to connect to sources of events and act on those events using rulebooks. For more information, see the [EDA documentation](https://ansible.readthedocs.io/projects/rulebook/en/latest/introduction.html).

Name | Description
--- | ---
[crowdstrike.falcon.eventstream](./docs/crowdstrike.falcon.eventstream.md) | Receive events from CrowdStrike Falcon Event Stream.

<!--end eda content-->

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

### Example Playbook

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

### Example Using the Event Stream EDA Source via Ansible Rulebook

> This example requires Ansible EDA to be installed. See the [Ansible Rulebook documentation](https://ansible.readthedocs.io/projects/rulebook/en/latest/getting_started.html) for more information.

```shell
ansible-rulebook -i inventory -r crowdstrike.falcon.event_stream_example -E FALCON_CLIENT_ID,FALCON_CLIENT_SECRET
```

## Installing on MacOS

Apple platforms require Mobile Device Management (MDM) software to install kernel extensions without user prompting.
Ansible is only able to run on macOS in an interactive session, which means end-users will receive prompts to accept the CrowdStrike kernel modules.

## Release Notes

See the [changelog](./CHANGELOG.rst) for a history of notable changes to this collection.

## More information

- [Ansible Collection Overview](https://github.com/ansible-collections/overview)
- [Ansible User Guide](https://docs.ansible.com/ansible/latest/user_guide/index.html)
- [Ansible Using Collections](https://docs.ansible.com/ansible/latest/user_guide/collections_using.html)
- [Ansible Community Code of Conduct](https://docs.ansible.com/ansible/latest/community/code_of_conduct.html)
- [Ansible Community Code of Conduct](https://docs.ansible.com/ansible/latest/community/code_of_conduct.html)
- [Ansible Rulebook Introduction](https://ansible.readthedocs.io/projects/rulebook/en/latest/getting_started.html)
- [Event Driven Ansible Introduction](https://www.ansible.com/blog/getting-started-with-event-driven-ansible)

## Contributing

If you want to develop new content or improve on this collection, please open an issue or create a pull request.
All contributions are welcome!

As of release > 3.2.18, we will now be following Ansible's development patterns for implementing Ansible's changelog fragments. This will require a changelog fragment to any PR that is not documentation or trivial. Most changelog entries will
likely be `bugfixes` or `minor_changes`. Please refer to the documentation for [Ansible's changelog fragments](https://docs.ansible.com/ansible/devel/community/development_process.html#creating-changelog-fragments) to learn more.

# License

See the [license](LICENSE) for more information.
