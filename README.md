[![Galaxy version](https://img.shields.io/badge/dynamic/json?style=flat&label=Galaxy&prefix=v&url=https://galaxy.ansible.com/api/v3/plugin/ansible/content/published/collections/index/crowdstrike/falcon/versions/?is_highest=true&query=data[0].version)](https://galaxy.ansible.com/ui/repo/published/crowdstrike/falcon/)
[![Ansible Lint](https://github.com/CrowdStrike/ansible_collection_falcon/actions/workflows/ansible-lint.yml/badge.svg)](https://github.com/CrowdStrike/ansible_collection_falcon/actions/workflows/ansible-lint.yml)
[![Ansible Test](https://github.com/CrowdStrike/ansible_collection_falcon/actions/workflows/ansible-test.yml/badge.svg)](https://github.com/CrowdStrike/ansible_collection_falcon/actions/workflows/ansible-test.yml)
[![YAML Lint](https://github.com/CrowdStrike/ansible_collection_falcon/actions/workflows/yamllint.yml/badge.svg)](https://github.com/CrowdStrike/ansible_collection_falcon/actions/workflows/yamllint.yml)
[![Python Lint](https://github.com/CrowdStrike/ansible_collection_falcon/actions/workflows/linting.yml/badge.svg)](https://github.com/CrowdStrike/ansible_collection_falcon/actions/workflows/linting.yml)

# Ansible Collection - crowdstrike.falcon

The Falcon Ansible Collection serves as a comprehensive toolkit for streamlining your interactions with the CrowdStrike Falcon platform.

## Ansible version compatibility

Tested with the Ansible Core >= 2.15.0 versions, and the current development version of Ansible. Ansible Core versions before 2.15.0 are not supported.

## Python version compatibility

This collection is reliant on the [CrowdStrike FalconPy SDK](https://www.falconpy.io/) for its Python interface. In line with the [Python versions supported by FalconPy](https://github.com/CrowdStrike/falconpy#supported-versions-of-python), a minimum Python version of `3.7` is required for this collection to function properly.

> [!NOTE]
> As of FalconPy Version 1.4.0, Python 3.6 is no longer supported. If you would like to use FalconPy with Python 3.6, please use FalconPy Version < 1.4.0.

## Included content

### Roles

Offering pre-defined roles tailored for various platforms—including macOS, Linux, and Windows—this collection simplifies the installation, configuration, and removal processes for CrowdStrike's Falcon sensor.

*Please read each role's README to familiarize yourself with the role variables and other requirements.*

| Role Name | Documentation
| --------- | :-----------:
| crowdstrike.falcon.falcon_install | [README](https://github.com/CrowdStrike/ansible_collection_falcon/blob/main/roles/falcon_install/README.md)
| crowdstrike.falcon.falcon_configure | [README](https://github.com/CrowdStrike/ansible_collection_falcon/blob/main/roles/falcon_configure/README.md)
| crowdstrike.falcon.falcon_uninstall | [README](https://github.com/CrowdStrike/ansible_collection_falcon/blob/main/roles/falcon_uninstall/README.md)

<!--start collection content-->
### Modules

Name | Description
--- | ---
[crowdstrike.falcon.falconctl](https://crowdstrike.github.io/ansible_collection_falcon/falconctl_module.html)|Configure CrowdStrike Falcon Sensor (Linux)
[crowdstrike.falcon.falconctl_info](https://crowdstrike.github.io/ansible_collection_falcon/falconctl_info_module.html)|Get Values Associated with Falcon Sensor (Linux)
[crowdstrike.falcon.fctl_child_cid_info](https://crowdstrike.github.io/ansible_collection_falcon/fctl_child_cid_info_module.html)|Retrieve details about Flight Control child CIDs
[crowdstrike.falcon.auth](https://crowdstrike.github.io/ansible_collection_falcon/auth_module.html)|Manage Authentication with Falcon API
[crowdstrike.falcon.cid_info](https://crowdstrike.github.io/ansible_collection_falcon/cid_info_module.html)|Get CID with checksum
[crowdstrike.falcon.host_contain](https://crowdstrike.github.io/ansible_collection_falcon/host_contain_module.html)|Network contain hosts in Falcon
[crowdstrike.falcon.host_hide](https://crowdstrike.github.io/ansible_collection_falcon/host_hide_module.html)|Hide/Unhide hosts from the Falcon console
[crowdstrike.falcon.host_info](https://crowdstrike.github.io/ansible_collection_falcon/host_info_module.html)|Get information about Falcon hosts
[crowdstrike.falcon.kernel_support_info](https://crowdstrike.github.io/ansible_collection_falcon/kernel_support_info_module.html)|Get information about kernels supported by the Falcon Sensor for Linux
[crowdstrike.falcon.sensor_download](https://crowdstrike.github.io/ansible_collection_falcon/sensor_download_module.html)|Download Falcon Sensor Installer
[crowdstrike.falcon.sensor_download_info](https://crowdstrike.github.io/ansible_collection_falcon/sensor_download_info_module.html)|Get information about Falcon Sensor Installers
[crowdstrike.falcon.sensor_update_builds_info](https://crowdstrike.github.io/ansible_collection_falcon/sensor_update_builds_info_module.html)|Get a list of available sensor build versions
[crowdstrike.falcon.sensor_update_policy_info](https://crowdstrike.github.io/ansible_collection_falcon/sensor_update_policy_info_module.html)|Get information about Falcon Update Sensor Policies

### Inventory plugins

Name | Description
--- | ---
[crowdstrike.falcon.falcon_discover](https://crowdstrike.github.io/ansible_collection_falcon/falcon_discover_inventory.html)|Falcon Discover inventory source
[crowdstrike.falcon.falcon_hosts](https://crowdstrike.github.io/ansible_collection_falcon/falcon_hosts_inventory.html)|Falcon Hosts inventory source

### Lookup plugins

Name | Description
--- | ---
[crowdstrike.falcon.fctl_child_cids](https://crowdstrike.github.io/ansible_collection_falcon/fctl_child_cids_lookup.html)|Fetch Flight Control child CIDs
[crowdstrike.falcon.host_ids](https://crowdstrike.github.io/ansible_collection_falcon/host_ids_lookup.html)|Fetch host IDs in Falcon
[crowdstrike.falcon.maintenance_token](https://crowdstrike.github.io/ansible_collection_falcon/maintenance_token_lookup.html)|Fetch maintenance token
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
      client_id: <FALCON_CLIENT_ID>
      client_secret: <FALCON_CLIENT_SECRET>
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
    falcon_client_id: <FALCON_CLIENT_ID>
    falcon_client_secret: <FALCON_CLIENT_SECRET>
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

## Questions or Support?

CrowdStrike Ansible Collection is a community-driven, open source project aimed at simplifying the integration and utilization of CrowdStrike's Falcon platform with Ansible automation. While not an official CrowdStrike product, the CrowdStrike Ansible Collection is maintained by CrowdStrike and supported in collaboration with the open source developer community.

For additional information, please refer to the [SUPPORT.md](./SUPPORT.md) file.

# License

See the [license](LICENSE) for more information.
