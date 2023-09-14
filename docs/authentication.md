# Authentication Guide

This guide outlines the different mechanisms available for authenticating with the CrowdStrike
Falcon API using Ansible modules based on FalconPy.

- [Environment Variables](#environment-variables)
- [Module Arguments](#module-arguments)
- [Auth Object](#auth-object)

## Environment Variables

Using environment variables is one way to store your Falcon API credentials.

To set these variables,
run the following commands in your terminal:

```terminal
export FALCON_CLIENT_ID='API CLIENT ID'
export FALCON_CLIENT_SECRET='API CLIENT SECRET'
```

If you would like to specify additional authentication environment variables:

```terminal
export FALCON_MEMBER_CID='MEMBER CID'
export FALCON_CLOUD='us-2'
```

## Module Arguments

Alternatively, you can pass in the credentials directly via module arguments:

> Highly recommended that you use Ansible vault or some other method of securing your credentials

```yaml
- crowdstrike.falcon.cid_info:
    client_id: "API CLIENT ID"
    client_secret: "API CLIENT SECRET"
    # Optional
    member_cid: "MEMBER CID"
    cloud: "eu-1"
  register: falcon_cid
```

## Auth Object

> Token based authentication

As a way to prevent the potential of being rate limited, we've introduced the ability to pass in an
authentication object which consists of an access token and the cloud region.

The `crowdstrike.falcon.auth` module can generate this object for you.

> :warning: The `cloud` region in the auth object may differ from the modules `cloud` argument due to auto-discovery.
>
> See the [FalconPy]([https://](https://www.falconpy.io/Usage/Environment-Configuration.html#cloud-region-autodiscovery)) docs for more information.

To generate an auth object:

```yaml
- name: Generate Authentication Object
  crowdstrike.falcon.auth:
    # If not using ENV variables, use module args here
  register: falcon
```

After obtaining the auth object, you can pass it to other modules to use the same authentication details:

```yaml
- name: Individually hide hosts with a list from the Falcon console
  crowdstrike.falcon.host_hide:
    auth: "{{ falcon.auth }}"
    hosts: "{{ item }}"
  loop: "{{ host_ids }}"
  register: hide_result
```
