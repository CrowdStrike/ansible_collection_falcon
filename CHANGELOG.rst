===================================================
Ansible CrowdStrike Falcon Collection Release Notes
===================================================

.. contents:: Topics


v3.2.25
=======

Release Summary
---------------

| Release Date: 2022-12-22
| `Release Notes: <https://github.com/CrowdStrike/ansible_collection_falcon/releases/tag/3.2.25>`__


Bugfixes
--------

- falcon_install - Fixed support for s390x that was causing issues for the other archs (https://github.com/CrowdStrike/ansible_collection_falcon/pull/281)

v3.2.24
=======

Release Summary
---------------

| Release Date: 2022-12-22
| `Release Notes: <https://github.com/CrowdStrike/ansible_collection_falcon/releases/tag/3.2.24>`__


Minor Changes
-------------

- falcon_install falcon_configure - Refactored API authentication for better useability (https://github.com/CrowdStrike/ansible_collection_falcon/pull/273)

Bugfixes
--------

- falcon_install - fix issue with sensor update policies and arch support (https://github.com/CrowdStrike/ansible_collection_falcon/pull/276)

v3.2.23
=======

Release Summary
---------------

| Release Date: 2022-10-10
| `Release Notes: <https://github.com/CrowdStrike/ansible_collection_falcon/releases/tag/3.2.23>`__


Minor Changes
-------------

- Updates made to conform with the latest ansible-lint rules (https://github.com/CrowdStrike/ansible_collection_falcon/pull/263)
- implement run_once playbook option to reduce API calls (https://github.com/CrowdStrike/ansible_collection_falcon/pull/261)

v3.2.22
=======

Release Summary
---------------

| Release Date: 2022-09-16
| `Release Notes: <https://github.com/CrowdStrike/ansible_collection_falcon/releases/tag/3.2.22>`__


Bugfixes
--------

- falcon_configure - fix issue with falcon_cloud variable not being set correctly (https://github.com/CrowdStrike/ansible_collection_falcon/issues/257)

v3.2.21
=======

Release Summary
---------------

| Release Date: 2022-09-06
| `Release Notes <https://github.com/CrowdStrike/ansible_collection_falcon/releases/tag/3.2.21>`__


Minor Changes
-------------

- falcon_install - add the ability to install from a local file (https://github.com/CrowdStrike/ansible_collection_falcon/pull/242).

Bugfixes
--------

- falcon_configure - fix issue with aid removal for image prep failed (https://github.com/CrowdStrike/ansible_collection_falcon/issues/254)

v3.2.20
=======

Release Summary
---------------

| Release Date: 2022-08-23
| `Release Notes <https://github.com/CrowdStrike/ansible_collection_falcon/releases/tag/3.2.19>`__


Bugfixes
--------

- falcon_install - fix-incorrect-arm64-assumptions (https://github.com/CrowdStrike/ansible_collection_falcon/issues/244)

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
