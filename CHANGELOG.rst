===================================================
Ansible CrowdStrike Falcon Collection Release Notes
===================================================

.. contents:: Topics


v3.2.19
=======

Release Summary
---------------

| Release Date: 2022-08-09
| `Release Notes: <https://github.com/CrowdStrike/ansible_collection_falcon/releases/tag/3.2.19>`__


Minor Changes
-------------

- ansible_install - added optional credentials for package download
- falcon_install - Update target_os for RHEL family to support RHEL 9.
- falconctl - Fixed issue with APD and billing options being able to use empty string as proper argument.
- falconctl - extrapolated common param checks to function.

Bugfixes
--------

- falconctl - updated usage of string options and added validation for options.
