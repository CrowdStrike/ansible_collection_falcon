![Ansible Lint](https://github.com/CrowdStrike/ansible-role-crowdstrike-falcon-installer/workflows/Ansible%20Lint/badge.svg)

Role Name
=========

A brief description of the role goes here.

Developer Requirements
----------------------
* This project uses GitHub pre-commit's to test changes locally. Visit https://pre-commit.com/#install to setup your dev machine. Cliff notes:

  * For OSX: ``pip install pre-commit``
  * For Ubuntu: ``sudo snap install pre-commit``

Requirements
------------

Any pre-requisites that may not be covered by Ansible itself or the role should be mentioned here. For instance, if the role uses the EC2 module, it may be a good idea to mention in this section that the boto package is required.

Role Variables
--------------

A description of the settable variables for this role should go here, including any variables that are in defaults/main.yml, vars/main.yml, and any variables that can/should be set via parameters to the role. Any variables that are read from other roles and/or the global scope (ie. hostvars, group vars, etc.) should be mentioned here as well.

Dependencies
------------

A list of other roles hosted on Galaxy should go here, plus any details in regards to parameters that may need to be set for other roles, or variables that are used from other roles.

Example Playbook
----------------

If performing a ``url`` based install:
```yaml
    - hosts: servers
      roles:
         - { role: crowdstrike.falcon_installer, crowdstrike.install_method: url, crowdstrike.download_url: https://fqdn/falcon-sensor.rpm, crowdstrike.cid: yourCID }
```

License
-------

BSD

Author Information
------------------

An optional section for the role authors to include contact information, or a website (HTML is not allowed).
