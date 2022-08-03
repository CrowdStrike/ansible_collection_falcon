.. _crowdstrike.falcon.falconctl_info_module:


*********************************
crowdstrike.falcon.falconctl_info
*********************************

**Get values associated with Falcon sensor.**


Version added: 3.2.0

.. contents::
   :local:
   :depth: 1


Synopsis
--------
- Return value associated with the Falcon sensor options.
- This module is similar to the GET option in falconctl cli.




Parameters
----------

.. raw:: html

    <table  border=0 cellpadding=0 class="documentation-table">
        <tr>
            <th colspan="1">Parameter</th>
            <th>Choices/<font color="blue">Defaults</font></th>
            <th width="100%">Comments</th>
        </tr>
            <tr>
                <td colspan="1">
                    <div class="ansibleOptionAnchor" id="parameter-"></div>
                    <b>name</b>
                    <a class="ansibleOptionLink" href="#parameter-" title="Permalink to this option"></a>
                    <div style="font-size: small">
                        <span style="color: purple">list</span>
                         / <span style="color: purple">elements=string</span>
                    </div>
                </td>
                <td>
                        <ul style="margin: 0; padding: 0"><b>Choices:</b>
                                    <li>cid</li>
                                    <li>aid</li>
                                    <li>apd</li>
                                    <li>aph</li>
                                    <li>app</li>
                                    <li>trace</li>
                                    <li>feature</li>
                                    <li>metadata_query</li>
                                    <li>message_log</li>
                                    <li>billing</li>
                                    <li>tags</li>
                                    <li>version</li>
                                    <li>rfm_state</li>
                                    <li>rfm_reason</li>
                        </ul>
                </td>
                <td>
                        <div>A list of falconctl GET options to query.</div>
                </td>
            </tr>
    </table>
    <br/>




Examples
--------

.. code-block:: yaml

    - name: Get all Falcon sensor options
      crowdstrike.falcon.falconctl_info:

    - name: Get a subset of Falcon sensor options
      crowdstike.falcon.falconctl_info:
        name:
          - 'cid'
          - 'aid'
          - 'tags'



Return Values
-------------
Common return values are documented `here <https://docs.ansible.com/ansible/latest/reference_appendices/common_return_values.html#common-return-values>`_, the following are the fields unique to this module:

.. raw:: html

    <table border=0 cellpadding=0 class="documentation-table">
        <tr>
            <th colspan="1">Key</th>
            <th>Returned</th>
            <th width="100%">Description</th>
        </tr>
            <tr>
                <td colspan="1">
                    <div class="ansibleOptionAnchor" id="return-"></div>
                    <b>falconctl_info</b>
                    <a class="ansibleOptionLink" href="#return-" title="Permalink to this return value"></a>
                    <div style="font-size: small">
                      <span style="color: purple">dictionary</span>
                    </div>
                </td>
                <td>success</td>
                <td>
                            <div>The dictionary containing values of requested Falcon sensor options.</div>
                            <div>Option values consist of strings, or null for options not set.</div>
                    <br/>
                        <div style="font-size: smaller"><b>Sample:</b></div>
                        <div style="font-size: smaller; color: blue; word-wrap: break-word; word-break: break-all;">{&#x27;cid&#x27;: &#x27;53abc1234c584115a46efc25dd831a2b&#x27;, &#x27;message_log&#x27;: &#x27;True&#x27;, &#x27;tags&#x27;: None}</div>
                </td>
            </tr>
    </table>
    <br/><br/>


Status
------


Authors
~~~~~~~

- Carlos Matos (@carlosmmatos)
- Gabriel Alford (@redhatrises)
