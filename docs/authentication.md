# Authentication Guide

The Falcon Ansible collection requires authenticating against the Falcon API. To do so you will
need client credentials. For more information see [Falcon API clients documentation](https://falcon.crowdstrike.com/documentation/page/a2a7fc0e/crowdstrike-oauth2-based-apis#mf8226da).

## Passing in credentials

You can pass in your Falcon API client credentials using either environment variables or 
module arguments. Available environment variables:

- `FALCON_CLIENT_ID` - required
- `FALCON_CLIENT_SECRET` - required
- `FALCON_CLOUD` - optional (discovered automatically)
- `FALCON_MEMBER_CID` - optional (only for Flight Control users)

Available module arguments:

```yaml
- crowdstrike.falcon.example_module:
    client_id: abcd1234 # required
    client_secret: abcd5678 # required
    cloud: us-2 # optional (discovered automatically)
    member_cid: abcd2468 # optional (only for Flight Control users)
```

You can use either of these methods for both authentication methods listed below.

## Authenticating with the Falcon API

### Recommended: token-based authentication

Token-based authentication allows you to authenticate once against the Falcon API, then use a 
returned temporary token for many subsequent API interactions. This is more efficient 
and also mitigates the risk of rate limiting, especially when automating multiple hosts. 
(For more information: [Falcon API rate limit documentation](https://falcon.crowdstrike.com/documentation/page/a2a7fc0e/crowdstrike-oauth2-based-apis#af41971e).)

To use token-based authentication, first use the `crowdstrike.falcon.auth` module to get a new token:

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
```

For more details on token-based authentication, see documentation for the `crowdstrike.falcon.auth` module.

### Alternative: per-task authentication

If you are only running a small number of tasks against the Falcon API, you can authenticate directly in the task:

```yaml
- crowdstrike.falcon.cid_info:
    client_id: "API CLIENT ID"
    client_secret: "API CLIENT SECRET"
    # Optional
    member_cid: "MEMBER CID"
    cloud: "eu-1"
  register: cid_info
```

Per-task authentication also supports environment variables:

```yaml
# assumes FALCON_CLIENT_ID and FALCON_CLIENT_SECRET have been set
- crowdstrike.falcon.cid_info:
  register: cid_info
```
