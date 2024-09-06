===================================================
Ansible CrowdStrike Falcon Collection Release Notes
===================================================

.. contents:: Topics

v4.6.0
======

Release Summary
---------------

| Release Date: 2024-09-06
| `Release Notes: <https://github.com/CrowdStrike/ansible_collection_falcon/releases/tag/4.6.0>`__

Minor Changes
-------------

- Enhance the info modules with how pagination is handled and clean options (https://github.com/CrowdStrike/ansible_collection_falcon/pull/558)
- allow become clause for Windows tasks to be toggable in each role (https://github.com/CrowdStrike/ansible_collection_falcon/pull/561)
- eventsource - add support for starting stream from latest event (https://github.com/CrowdStrike/ansible_collection_falcon/pull/552)
- falcon_discover - Added ability to allow duplicate hosts in the same environment (https://github.com/CrowdStrike/ansible_collection_falcon/pull/551)
- kernel_support_info - Add support for paginating kernel support information (https://github.com/CrowdStrike/ansible_collection_falcon/pull/557)

Bugfixes
--------

- eventsource - fix issue with refreshinterval causing timeout (https://github.com/CrowdStrike/ansible_collection_falcon/pull/552)

v4.5.2
======

Release Summary
---------------

| Release Date: 2024-08-15
| `Release Notes: <https://github.com/CrowdStrike/ansible_collection_falcon/releases/tag/4.5.2>`__

Bugfixes
--------

- falcon_configure - fixed issue with master image and provisioning tokens (https://github.com/CrowdStrike/ansible_collection_falcon/pull/546)
- falconct_info - added support for querying provisioning tokens (https://github.com/CrowdStrike/ansible_collection_falcon/pull/546)

v4.5.1
======

Release Summary
---------------

| Release Date: 2024-06-28
| `Release Notes: <https://github.com/CrowdStrike/ansible_collection_falcon/releases/tag/4.5.1>`__

Bugfixes
--------

- falcon_install - fix failed gpg key installs for new sensors (https://github.com/CrowdStrike/ansible_collection_falcon/pull/537)
- falcon_install - fix filter to take advantage of new architectures field (https://github.com/CrowdStrike/ansible_collection_falcon/pull/521)
- falcon_uninstall - fix become clause for remove_host_pretasks.yml (https://github.com/CrowdStrike/ansible_collection_falcon/pull/532)
- sensor_download_info - fix offset and use override for v2 endpoint (https://github.com/CrowdStrike/ansible_collection_falcon/pull/520)

v4.5.0
======

Release Summary
---------------

| Release Date: 2024-05-16
| `Release Notes: <https://github.com/CrowdStrike/ansible_collection_falcon/releases/tag/4.5.0>`__

Minor Changes
-------------

- fctl_child_cid_info - Added new module to get information about Flight Control child CIDs (https://github.com/CrowdStrike/ansible_collection_falcon/pull/517)
- fctl_child_cids - new lookup filter plugin to fetch child cids (https://github.com/CrowdStrike/ansible_collection_falcon/pull/516)

New Plugins
-----------

Lookup
~~~~~~

- crowdstrike.falcon.fctl_child_cids - fetch Flight Control child CIDs

New Modules
-----------

- crowdstrike.falcon.fctl_child_cid_info - Retrieve details about Flight Control child CIDs

v4.4.0
======

Release Summary
---------------

| Release Date: 2024-05-06
| `Release Notes: <https://github.com/CrowdStrike/ansible_collection_falcon/releases/tag/4.4.0>`__

Minor Changes
-------------

- host_ids - adds a new lookup plugin for getting host IDs (https://github.com/CrowdStrike/ansible_collection_falcon/pull/503)
- host_info - adds new module for retrieving host details (https://github.com/CrowdStrike/ansible_collection_falcon/pull/504)
- kernel_support_info - adds new module for kernel support information (https://github.com/CrowdStrike/ansible_collection_falcon/pull/499)
- sensor_update_builds_info - adds new module for retrieving sensor build versions (https://github.com/CrowdStrike/ansible_collection_falcon/pull/500)

New Plugins
-----------

Lookup
~~~~~~

- crowdstrike.falcon.host_ids - fetch host IDs (AIDs)
- crowdstrike.falcon.maintenance_token - fetch maintenance token

New Modules
-----------

- crowdstrike.falcon.host_info - Get information about Falcon hosts
- crowdstrike.falcon.sensor_update_builds_info - Get a list of available sensor build versions

v4.3.2
======

Release Summary
---------------

| Release Date: 2024-04-09
| `Release Notes: <https://github.com/CrowdStrike/ansible_collection_falcon/releases/tag/4.3.2>`__

Bugfixes
--------

- falcon_install - allow permissions for sensor download task (https://github.com/CrowdStrike/ansible_collection_falcon/pull/497)

v4.3.1
======

Release Summary
---------------

| Release Date: 2024-04-08
| `Release Notes: <https://github.com/CrowdStrike/ansible_collection_falcon/releases/tag/4.3.1>`__

Bugfixes
--------

- falcon_configure - updated logic to remove aid during configuration stage (https://github.com/CrowdStrike/ansible_collection_falcon/pull/486)
- sensor_download - added the ability to set file permissions on downloaded files (https://github.com/CrowdStrike/ansible_collection_falcon/pull/485)

v4.3.0
======

Release Summary
---------------

| Release Date: 2024-03-27
| `Release Notes: <https://github.com/CrowdStrike/ansible_collection_falcon/releases/tag/4.3.0>`__

Minor Changes
-------------

- falcon_hosts - adds a new dynamic inventory for the Hosts service collection (https://github.com/CrowdStrike/ansible_collection_falcon/pull/470)

Bugfixes
--------

- falcon_hosts - added support for hostname preferences and fixed documentation (https://github.com/CrowdStrike/ansible_collection_falcon/pull/474)
- falcon_hosts - added support for parameter templating (https://github.com/CrowdStrike/ansible_collection_falcon/pull/475)
- host_hide - api action was limited to 100 hosts. Fix now allows for processing of more than 100 hosts. (https://github.com/CrowdStrike/ansible_collection_falcon/pull/473)

New Plugins
-----------

Inventory
~~~~~~~~~

- crowdstrike.falcon.falcon_hosts - CrowdStrike Falcon Hosts inventory source

v4.2.2
======

Release Summary
---------------

| Release Date: 2024-02-14
| `Release Notes: <https://github.com/CrowdStrike/ansible_collection_falcon/releases/tag/4.2.2>`__

Bugfixes
--------

- Remove superfluous parameter `required` from process.get_bin_path API usage.
- falcon_install - fix falcon_target_os value for SLES (https://github.com/CrowdStrike/ansible_collection_falcon/pull/449)

v4.2.1
======

Release Summary
---------------

| Release Date: 2023-12-08
| `Release Notes: <https://github.com/CrowdStrike/ansible_collection_falcon/releases/tag/4.2.1>`__

v4.2.0
======

Release Summary
---------------

| Release Date: 2023-10-19
| `Release Notes: <https://github.com/CrowdStrike/ansible_collection_falcon/releases/tag/4.2.0>`__

Minor Changes
-------------

- eventstream plugin - add user-agent string (https://github.com/CrowdStrike/ansible_collection_falcon/pull/426)

v4.1.3
======

Release Summary
---------------

| Release Date: 2023-09-22
| `Release Notes: <https://github.com/CrowdStrike/ansible_collection_falcon/releases/tag/4.1.3>`__

Bugfixes
--------

- falcon_configure - fix main task call to auth task (https://github.com/CrowdStrike/ansible_collection_falcon/pull/418)

v4.1.2
======

Release Summary
---------------

| Release Date: 2023-09-19
| `Release Notes: <https://github.com/CrowdStrike/ansible_collection_falcon/releases/tag/4.1.2>`__

Bugfixes
--------

- falconpy_utils - fix incorrect url for eu1 (https://github.com/CrowdStrike/ansible_collection_falcon/pull/415)

v4.1.1
======

Release Summary
---------------

| Release Date: 2023-09-17
| `Release Notes: <https://github.com/CrowdStrike/ansible_collection_falcon/releases/tag/4.1.1>`__

Bugfixes
--------

- falcon_discover - fixed missing parameter for compose to work properly (https://github.com/CrowdStrike/ansible_collection_falcon/pull/413)

v4.1.0
======

Release Summary
---------------

| Release Date: 2023-09-16
| `Release Notes: <https://github.com/CrowdStrike/ansible_collection_falcon/releases/tag/4.1.0>`__

Minor Changes
-------------

- host_contain - adds new module to manage host network containment state (https://github.com/CrowdStrike/ansible_collection_falcon/pull/411)

New Modules
-----------

- crowdstrike.falcon.host_contain - Network contain hosts in Falcon

v4.0.0
======

Release Summary
---------------

| Release Date: 2023-09-15
| `Release Notes: <https://github.com/CrowdStrike/ansible_collection_falcon/releases/tag/4.0.0>`__

Minor Changes
-------------

- auth - adds ``auth`` module to manage authentication with the Falcon API (https://github.com/CrowdStrike/ansible_collection_falcon/pull/384)
- cid_info - adds ``cid_info`` module to help retrieve CID with checksum (https://github.com/CrowdStrike/ansible_collection_falcon/pull/395)
- falcon_discover - adds a new dynamic inventory for the Discover service collection (https://github.com/CrowdStrike/ansible_collection_falcon/pull/400)
- falcon_install - replaces existing API functionality with new modules (https://github.com/CrowdStrike/ansible_collection_falcon/pull/396)
- host_hide - adds ``host_hide`` module to hide/unhide hosts from the Falcon console (https://github.com/CrowdStrike/ansible_collection_falcon/pull/399)
- sensor_download - adds ``sensor_download`` module to download sensor from the Falcon API (https://github.com/CrowdStrike/ansible_collection_falcon/pull/396)
- sensor_download_info - adds ``sensor_download_info`` module to retrieve sensor installers to download (https://github.com/CrowdStrike/ansible_collection_falcon/pull/396)
- sensor_policy_info - adds ``sensor_policy_info`` module to retrieve sensor policy information from the CrowdStrike Falcon API (https://github.com/CrowdStrike/ansible_collection_falcon/pull/251)

Breaking Changes / Porting Guide
--------------------------------

- falconpy - new collection requirements for authenticating with the CrowdStrike Falcon API now require the falconpy sdk. All existing roles within the collection have been ported over and should use the ``./requirements.txt`` file to get started. (https://github.com/CrowdStrike/ansible_collection_falcon/pull/384)

Bugfixes
--------

- cid_info - return the first element of the array (https://github.com/CrowdStrike/ansible_collection_falcon/pull/396)
- falcon_configure - add missing when clause for mac task (https://github.com/CrowdStrike/ansible_collection_falcon/pull/399)

New Plugins
-----------

Inventory
~~~~~~~~~

- crowdstrike.falcon.falcon_discover - CrowdStrike Falcon Discover inventory source

New Modules
-----------

- crowdstrike.falcon.auth - Manage authentication
- crowdstrike.falcon.cid_info - Get CID with checksum
- crowdstrike.falcon.host_hide - Hide/Unhide hosts from the Falcon console
- crowdstrike.falcon.sensor_download - Download Falcon Sensor Installer
- crowdstrike.falcon.sensor_download_info - Get information about Falcon Sensor Installers
- crowdstrike.falcon.sensor_update_policy_info - Get information about Falcon Update Sensor Policies

v3.3.3
======

Release Summary
---------------

| Release Date: 2023-09-14
| `Release Notes: <https://github.com/CrowdStrike/ansible_collection_falcon/releases/tag/3.3.3>`__

Bugfixes
--------

- update ansible meta information for certifiable requirements (https://github.com/CrowdStrike/ansible_collection_falcon/pull/405)

v3.3.2
======

Release Summary
---------------

| Release Date: 2023-09-11
| `Release Notes: <https://github.com/CrowdStrike/ansible_collection_falcon/releases/tag/3.3.2>`__

Minor Changes
-------------

- falcon_uninstall - Adds hide/remove host functionality (https://github.com/CrowdStrike/ansible_collection_falcon/pull/393)

Bugfixes
--------

- falcon_configure - add become clause to remove_aid tasks (https://github.com/CrowdStrike/ansible_collection_falcon/pull/392)

v3.3.1
======

Release Summary
---------------

| Release Date: 2023-08-17
| `Release Notes: <https://github.com/CrowdStrike/ansible_collection_falcon/releases/tag/3.3.1>`__

Bugfixes
--------

- eda - fix EDA partner requirements using tox (https://github.com/CrowdStrike/ansible_collection_falcon/pull/381)

v3.3.0
======

Release Summary
---------------

| Release Date: 2023-08-04
| `Release Notes: <https://github.com/CrowdStrike/ansible_collection_falcon/releases/tag/3.3.0>`__

Minor Changes
-------------

- evenstream-eda - Introducing new EvenStream EDA plugin (https://github.com/CrowdStrike/ansible_collection_falcon/pull/322)

Bugfixes
--------

- falcon_install - Fix Windows destination URL (https://github.com/CrowdStrike/ansible_collection_falcon/pull/375)

v3.2.36
=======

Release Summary
---------------

| Release Date: 2023-07-28
| `Release Notes: <https://github.com/CrowdStrike/ansible_collection_falcon/releases/tag/3.2.36>`__

Minor Changes
-------------

- falcon_install - add the ability to install from an URL for windows (https://github.com/CrowdStrike/ansible_collection_falcon/pull/363)
- falcon_install - removing kernel compat check due to prevelance of ebpf (https://github.com/CrowdStrike/ansible_collection_falcon/pull/367)

Bugfixes
--------

- falcon_install - use tmp path instead of hardcoding sensor name (https://github.com/CrowdStrike/ansible_collection_falcon/pull/368)

v3.2.35
=======

Release Summary
---------------

| Release Date: 2023-06-30
| `Release Notes: <https://github.com/CrowdStrike/ansible_collection_falcon/releases/tag/3.2.35>`__

Bugfixes
--------

- falcon_install - fix issue with expired gpg key (https://github.com/CrowdStrike/ansible_collection_falcon/pull/361)

v3.2.34
=======

Release Summary
---------------

| Release Date: 2023-05-10
| `Release Notes: <https://github.com/CrowdStrike/ansible_collection_falcon/releases/tag/3.2.34>`__

Bugfixes
--------

- falcon_install - fix bug with zypper downgrade (https://github.com/CrowdStrike/ansible_collection_falcon/pull/344)

v3.2.33
=======

Release Summary
---------------

| Release Date: 2023-04-24
| `Release Notes: <https://github.com/CrowdStrike/ansible_collection_falcon/releases/tag/3.2.33>`__

Minor Changes
-------------

- falcon_install - gives the user the option to downgrade the falcon sensor to a previous version (https://github.com/CrowdStrike/ansible_collection_falcon/pull/334)

v3.2.32
=======

Release Summary
---------------

| Release Date: 2023-03-30
| `Release Notes: <https://github.com/CrowdStrike/ansible_collection_falcon/releases/tag/3.2.32>`__

Bugfixes
--------

- falcon_install - fix issue with sorting of returned versions when using falcon_sensor_version_decrement (https://github.com/CrowdStrike/ansible_collection_falcon/pull/325)
- falcon_install - fix kernel compatibility query (https://github.com/CrowdStrike/ansible_collection_falcon/pull/332)

v3.2.31
=======

Release Summary
---------------

| Release Date: 2023-03-15
| `Release Notes: <https://github.com/CrowdStrike/ansible_collection_falcon/releases/tag/3.2.31>`__

Minor Changes
-------------

- falcon_configure - adds the ability to manage grouping tags for Mac OS (https://github.com/CrowdStrike/ansible_collection_falcon/pull/318)
- falcon_install - made the ability to toggle run_once options available to the user (https://github.com/CrowdStrike/ansible_collection_falcon/pull/320)
- falcon_install, falcon_configure, falcon_uninstall - Enhances the roles to better support Mac OS, to include changed_when and failed_when conditions (https://github.com/CrowdStrike/ansible_collection_falcon/pull/318/files)

Bugfixes
--------

- falcon_install - fixes a bug where falcon_os_arch was affecting the falcon_install module on Mac OS X (https://github.com/CrowdStrike/ansible_collection_falcon/pull/318)

v3.2.30
=======

Release Summary
---------------

| Release Date: 2023-03-06
| `Release Notes: <https://github.com/CrowdStrike/ansible_collection_falcon/releases/tag/3.2.30>`__

Bugfixes
--------

- falcon_install - fix win auth (https://github.com/CrowdStrike/ansible_collection_falcon/pull/316)

v3.2.29
=======

Release Summary
---------------

| Release Date: 2023-03-01
| `Release Notes: <https://github.com/CrowdStrike/ansible_collection_falcon/releases/tag/3.2.29>`__

Minor Changes
-------------

- falcon_configure, falcon_install - Extract authentication logic to be more OS specific (https://github.com/CrowdStrike/ansible_collection_falcon/pull/309)

v3.2.28
=======

Release Summary
---------------

| Release Date: 2023-02-16
| `Release Notes: <https://github.com/CrowdStrike/ansible_collection_falcon/releases/tag/3.2.28>`__

Minor Changes
-------------

- falcon_configure, falcon_install, falcon_uninstall - Updated to use ansible facts dictionary instead of the ansible_* naming convention (https://github.com/CrowdStrike/ansible_collection_falcon/pull/299)
- falcon_install - Fix delegate_to issue due to omit bug in Ansible 2.12 (https://github.com/CrowdStrike/ansible_collection_falcon/pull/306)

v3.2.27
=======

Release Summary
---------------

| Release Date: 2023-01-12
| `Release Notes: <https://github.com/CrowdStrike/ansible_collection_falcon/releases/tag/3.2.27>`__

Minor Changes
-------------

- falcon_configure - Add backend support for bpf (https://github.com/CrowdStrike/ansible_collection_falcon/pull/287)
- falcon_install - Fixed issue with delegation in Auth call (https://github.com/CrowdStrike/ansible_collection_falcon/pull/286)
- falconctl, falconctl_info - Add backend option support for bpf (https://github.com/CrowdStrike/ansible_collection_falcon/pull/287)

v3.2.26
=======

Release Summary
---------------

| Release Date: 2022-12-27
| `Release Notes: <https://github.com/CrowdStrike/ansible_collection_falcon/releases/tag/3.2.26>`__

Bugfixes
--------

- falcon_install - Fix issue with non-linux systems being affected by `falcon_os_arch` variable (https://github.com/CrowdStrike/ansible_collection_falcon/pull/284)

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
