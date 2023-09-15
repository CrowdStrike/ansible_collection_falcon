[![Galaxy version](https://img.shields.io/badge/dynamic/json?style=flat&label=galaxy&prefix=v&url=https://galaxy.ansible.com/api/v2/collections/crowdstrike/falcon/&query=latest_version.version)](https://galaxy.ansible.com/CrowdStrike/falcon)
[![Ansible Lint](https://github.com/CrowdStrike/ansible_collection_falcon/actions/workflows/ansible-lint.yml/badge.svg)](https://github.com/CrowdStrike/ansible_collection_falcon/actions/workflows/ansible-lint.yml)
[![Ansible Test](https://github.com/CrowdStrike/ansible_collection_falcon/actions/workflows/ansible-test.yml/badge.svg)](https://github.com/CrowdStrike/ansible_collection_falcon/actions/workflows/ansible-test.yml)
[![YAML Lint](https://github.com/CrowdStrike/ansible_collection_falcon/actions/workflows/yamllint.yml/badge.svg)](https://github.com/CrowdStrike/ansible_collection_falcon/actions/workflows/yamllint.yml)
[![Python Lint](https://github.com/CrowdStrike/ansible_collection_falcon/actions/workflows/linting.yml/badge.svg)](https://github.com/CrowdStrike/ansible_collection_falcon/actions/workflows/linting.yml)

# Ansible Collection - crowdstrike.falcon

The Falcon Ansible Collection serves as a comprehensive toolkit for streamlining your interactions with the CrowdStrike Falcon platform.

## :mega: Announcements

**September 15, 2023:** We are excited to announce that Version 4 of the Falcon Ansible Collection has been officially launched. Version 4 will provide us with numerous
advantages that align well with our ongoing automation and cybersecurity strategies. By extending the power of the FalconPy SDK, Version 4 will be instrumental in interacting with
and automating the Falcon platform.

### Important Notice for Version 3

- **New Branch:** Version 3 will be moved to its own dedicated branch [v3](https://github.com/CrowdStrike/ansible_collection_falcon/tree/v3) to allow for isolated maintenance
  and bug fixes.
- **No New Features:** Version 3 will not receive any new features moving forward. We will only release bug fixes to maintain its stability. This is to allow us to focus our
  development efforts on Version 4.
- **Limited Support:** Version 3 will continue to receive bug fixes until **February 1st, 2024**. After that date, we will no longer provide updates or support for Version 3.

### How to upgrade

We strongly encourage you to upgrade to Version 4 to benefit from new features and ongoing support. Please see the [Installing this collection](#installing-this-collection) section to get started.

### Questions or concerns?

If you encounter any issues or have questions about the migration, please open an [issue](https://github.com/CrowdStrike/ansible_collection_falcon/issues/new/choose) in this repository.

## Ansible version compatibility

Tested with the Ansible Core >= 2.13.0 versions, and the current development version of Ansible. Ansible Core versions before 2.13.0 are not supported.

## Python version compatibility

This collection is reliant on the [CrowdStrike FalconPy SDK](https://www.falconpy.io/) for its Python interface. In line with the [Python versions supported by FalconPy](https://github.com/CrowdStrike/falconpy#supported-versions-of-python), a minimum Python version of `3.6` is required for this collection to function properly.

## Included content

### Roles

Offering pre-defined roles tailored for various platforms—including macOS, Linux, and Windows—this collection simplifies the installation, configuration, and removal processes for CrowdStrike's Falcon sensor.

*Please read each role's README to familiarize yourself with the role variables and other requirements.*

| Role Name | Documentation | Build Status Linux | Build Status Windows |
| --------- | :-----------: | ------------------ | -------------------- |
| crowdstrike.falcon.falcon_install | [README](https://github.com/CrowdStrike/ansible_collection_falcon/blob/main/roles/falcon_install/README.md) | [![falcon_install](https://github.com/CrowdStrike/ansible_collection_falcon/actions/workflows/falcon_install.yml/badge.svg)](https://github.com/CrowdStrike/ansible_collection_falcon/actions/workflows/falcon_install.yml) | [![falcon_install](https://github.com/CrowdStrike/ansible_collection_falcon/actions/workflows/win_falcon_install.yml/badge.svg)](https://github.com/CrowdStrike/ansible_collection_falcon/actions/workflows/win_falcon_install.yml)
| crowdstrike.falcon.falcon_configure | [README](https://github.com/CrowdStrike/ansible_collection_falcon/blob/main/roles/falcon_configure/README.md) | [![falcon_configure](https://github.com/CrowdStrike/ansible_collection_falcon/actions/workflows/falcon_configure.yml/badge.svg)](https://github.com/CrowdStrike/ansible_collection_falcon/actions/workflows/falcon_configure.yml) | [![falcon_configure](https://github.com/CrowdStrike/ansible_collection_falcon/actions/workflows/win_falcon_configure.yml/badge.svg)](https://github.com/CrowdStrike/ansible_collection_falcon/actions/workflows/win_falcon_configure.yml)
| crowdstrike.falcon.falcon_uninstall | [README](https://github.com/CrowdStrike/ansible_collection_falcon/blob/main/roles/falcon_uninstall/README.md) | [![falcon_uninstall](https://github.com/CrowdStrike/ansible_collection_falcon/actions/workflows/falcon_uninstall.yml/badge.svg)](https://github.com/CrowdStrike/ansible_collection_falcon/actions/workflows/falcon_uninstall.yml) | [![falcon_uninstall](https://github.com/CrowdStrike/ansible_collection_falcon/actions/workflows/win_falcon_uninstall.yml/badge.svg)](https://github.com/CrowdStrike/ansible_collection_falcon/actions/workflows/win_falcon_uninstall.yml)

<!--start collection content-->
### Modules

Name | Description
--- | ---
[crowdstrike.falcon.falconctl](https://crowdstrike.github.io/ansible_collection_falcon/falconctl_module.html#ansible-collections-crowdstrike-falcon-falconctl-module)|Configure CrowdStrike Falcon Sensor (Linux)
[crowdstrike.falcon.falconctl_info](https://crowdstrike.github.io/ansible_collection_falcon/falconctl_info_module.html#ansible-collections-crowdstrike-falcon-falconctl-info-module)|Get Values Associated with Falcon Sensor (Linux)
[crowdstrike.falcon.auth](https://crowdstrike.github.io/ansible_collection_falcon/auth.html#ansible-collections-crowdstrike-falcon-auth-module)|Manage Authentication with Falcon API
[crowdstrike.falcon.cid_info](https://crowdstrike.github.io/ansible_collection_falcon/cid_info.html#ansible-collections-crowdstrike-falcon-cid-info-module)|Get CID with checksum
[crowdstrike.falcon.host_hide](https://crowdstrike.github.io/ansible_collection_falcon/host_hide.html#ansible-collections-crowdstrike-falcon-host-hide-module)|Hide/Unhide hosts from the Falcon console
[crowdstrike.falcon.sensor_download](https://crowdstrike.github.io/ansible_collection_falcon/sensor_download.html#ansible-collections-crowdstrike-falcon-sensor-download-module)|Download Falcon Sensor Installer
[crowdstrike.falcon.sensor_download_info](https://crowdstrike.github.io/ansible_collection_falcon/sensor_download_info.html#ansible-collections-crowdstrike-falcon-sensor-download-info-module)|Get information about Falcon Sensor Installers
[crowdstrike.falcon.sensor_update_policy_info](https://crowdstrike.github.io/ansible_collection_falcon/sensor_update_policy_info.html#ansible-collections-crowdstrike-falcon-sensor-update-policy-info-module)|Get information about Falcon Update Sensor Policies

### Inventory plugins

Name | Description
--- | ---
[crowdstrike.falcon.falcon_discover](https://crowdstrike.github.io/ansible_collection_falcon/falcon_discover_inventory.html#ansible-collections-crowdstrike-falcon-falcon-discover-inventory-plugin)|Falcon Discover inventory source
<!--end collection content-->

<!--start eda content-->
### Event sources

Ansible EDA (Event Driven Ansible) is a new way to connect to sources of events and act on those events using rulebooks. For more information, see the [EDA documentation](https://ansible.readthedocs.io/projects/rulebook/en/latest/introduction.html).

Name | Description
--- | ---
[crowdstrike.falcon.eventstream](./docs/crowdstrike.falcon.eventstream.md) | Receive events from CrowdStrike Falcon Event Stream.

<!--end eda content-->

## Installing this collection

### Using `ansible-galaxy` CLI

To install the Falcon Ansible Collection using the command-line interface, execute the following:

```terminal
ansible-galaxy collection install crowdstrike.falcon
```

### Using a `requirements.yml` File

To include the collection in a `requirements.yml` file and install it through `ansible-galaxy`, use the following format:

```yaml
---
collections:
  - crowdstrike.falcon
```

Then run:

```terminal
ansible-galaxy collection install -r requirements.yml
```

### Additional notes

- **Upgrading the Collection**: Note that if you've installed the collection from Ansible Galaxy, it won't automatically update when you upgrade the `ansible` package. To manually upgrade to the latest version, use:

    ```terminal
    ansible-galaxy collection install crowdstrike.falcon --upgrade
    ```

- **Installing a Specific Version**: If you need to install a particular version of the collection (for example, to downgrade due to an issue), you can specify the version as follows:

    ```terminal
    ansible-galaxy collection install crowdstrike.falcon:==0.1.0
    ```

### Python dependencies

The Python module dependencies are not automatically handled by `ansible-galaxy`. To manually install these dependencies, you have the following options:

1. Utilize the `requirements.txt` file to install all required packages:

    ```terminal
    pip install -r requirements.txt
    ```

2. Alternatively, install the CrowdStrike FalconPy package directly:

    ```terminal
    pip install crowdstrike-falconpy
    ```

> [!NOTE]
> If you intend to use Event-Driven Ansible (EDA), the `aiohttp` package should also be installed.

## Authentication

To use this Ansible collection effectively, you'll need to authenticate with the CrowdStrike Falcon API. We've prepared a detailed guide
outlining the various authentication mechanisms supported. Check out the [Authentication Guide](docs/authentication.md) for step-by-step instructions.

## Using this collection

### Example using modules

```yaml
---
  - name: Get a list of the 2 latest Windows Sensor Installers
    crowdstrike.falcon.sensor_download_info:
      client_id: <Falcon_UI_OAUTH_client_id>
      client_secret: <Falcon_UI_OAUTH_client_secret>
      cloud: us-2
      limit: 2
      filter: "platform_name:'windows'"
      sort: "version|desc"
    delegate_to: localhost
```

### Example using the built-in roles to install Falcon

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

### Example using the Event Stream EDA source via Ansible Rulebook

This example requires Ansible EDA to be installed. See the [Ansible Rulebook documentation](https://ansible.readthedocs.io/projects/rulebook/en/latest/getting_started.html) for more information.

```shell
ansible-rulebook -i inventory -r crowdstrike.falcon.event_stream_example -E FALCON_CLIENT_ID,FALCON_CLIENT_SECRET
```

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
- [CrowdStrike FalconPy SDK](https://www.falconpy.io/)

## Contributing

If you want to develop new content or improve on this collection, please open an issue or create a pull request.
All contributions are welcome!

As of release > 3.2.18, we will now be following Ansible's development patterns for implementing Ansible's changelog fragments. This will require a changelog fragment to any PR that is not documentation or trivial. Most changelog entries will
likely be `bugfixes` or `minor_changes`. Please refer to the documentation for [Ansible's changelog fragments](https://docs.ansible.com/ansible/devel/community/development_process.html#creating-changelog-fragments) to learn more.

# License

See the [license](LICENSE) for more information.
