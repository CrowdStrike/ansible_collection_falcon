falcon_configure
=========

This role will configure the CrowdStrike Falcon Sensor.

Requirements
------------

Ansible 2.10 or higher

Role Variables
--------------

 * `falcon_cid` - Your Falcon Customer ID (CID) (string, default: null)
 * `falcon_provisioning_token` - Falcon Installation Token (string, default: null)

Dependencies
------------

- Privilege escalation (sudo) is required for this role to function properly.

Example Playbook
----------------

This example shows how to set your Customer ID (CID):
```yaml
- hosts: all
- name: Set CrowdStrike Falcon CID
  crowdstrike.falcon.falconctl:
    state: present
    cid: 1234567890ABCDEF1234567890ABCDEF-12

- name: Set CrowdStrike Falcon CID with Provisioning Token
  crowdstrike.falcon.falconctl:
    state: present
    cid: 1234567890ABCDEF1234567890ABCDEF-12
    provisioning_token: 12345678

- name: Delete CrowdStrike Falcon CID
  crowdstrike.falcon.falconctl:
    state: absent
    cid: 1234567890ABCDEF1234567890ABCDEF-12

- name: Delete Agent ID to Prep Master Image
  crowdstrike.falcon.falconctl:
    state: absent
    aid: yes

- name: Configure Falcon Sensor Proxy
  crowdstrike.falcon.falconctl:
    state: present
    apd: yes
    aph: http://example.com
    app: 8080

License
-------

BSD

Author Information
------------------

An optional section for the role authors to include contact information, or a website (HTML is not allowed).
