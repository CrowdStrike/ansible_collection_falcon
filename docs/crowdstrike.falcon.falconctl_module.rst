.. _crowdstrike.falcon.falconctl_module:


****************************
crowdstrike.falcon.falconctl
****************************

**Configure CrowdStrike Falcon Sensor**


Version added: 3.2.0

.. contents::
   :local:
   :depth: 1


Synopsis
--------
- Configures CrowdStrike Falcon Sensor on Linux systems




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
                    <b>aid</b>
                    <a class="ansibleOptionLink" href="#parameter-" title="Permalink to this option"></a>
                    <div style="font-size: small">
                        <span style="color: purple">boolean</span>
                    </div>
                </td>
                <td>
                        <ul style="margin: 0; padding: 0"><b>Choices:</b>
                                    <li>no</li>
                                    <li>yes</li>
                        </ul>
                </td>
                <td>
                        <div>Whether or not you would like to delete the associated Agent ID.</div>
                        <div>Useful when preparing a host as a master image for cloning or virtualization.</div>
                        <div>This applies only to <code>state=absent</code>.</div>
                </td>
            </tr>
            <tr>
                <td colspan="1">
                    <div class="ansibleOptionAnchor" id="parameter-"></div>
                    <b>apd</b>
                    <a class="ansibleOptionLink" href="#parameter-" title="Permalink to this option"></a>
                    <div style="font-size: small">
                        <span style="color: purple">string</span>
                    </div>
                </td>
                <td>
                        <ul style="margin: 0; padding: 0"><b>Choices:</b>
                                    <li>True</li>
                                    <li>true</li>
                                    <li>False</li>
                                    <li>false</li>
                                    <li></li>
                        </ul>
                </td>
                <td>
                        <div>Whether to enable or disable the Falcon sensor to use a proxy.</div>
                        <div>To enable the proxy, set to <code>false|no</code>.</div>
                </td>
            </tr>
            <tr>
                <td colspan="1">
                    <div class="ansibleOptionAnchor" id="parameter-"></div>
                    <b>aph</b>
                    <a class="ansibleOptionLink" href="#parameter-" title="Permalink to this option"></a>
                    <div style="font-size: small">
                        <span style="color: purple">string</span>
                    </div>
                </td>
                <td>
                </td>
                <td>
                        <div>Specifies the application proxy host to use for Falcon sensor proxy configuration.</div>
                </td>
            </tr>
            <tr>
                <td colspan="1">
                    <div class="ansibleOptionAnchor" id="parameter-"></div>
                    <b>app</b>
                    <a class="ansibleOptionLink" href="#parameter-" title="Permalink to this option"></a>
                    <div style="font-size: small">
                        <span style="color: purple">string</span>
                    </div>
                </td>
                <td>
                </td>
                <td>
                        <div>Specifies the application proxy port to use for Falcon sensor proxy configuration.</div>
                </td>
            </tr>
            <tr>
                <td colspan="1">
                    <div class="ansibleOptionAnchor" id="parameter-"></div>
                    <b>billing</b>
                    <a class="ansibleOptionLink" href="#parameter-" title="Permalink to this option"></a>
                    <div style="font-size: small">
                        <span style="color: purple">string</span>
                    </div>
                </td>
                <td>
                </td>
                <td>
                        <div>Specify the (Pay-As-You-Go) billing model for Cloud Workloads.</div>
                        <div>Falcon for Cloud Workloads (Pay-As-You-Go) is a billing model for your hosts that run in Amazon Web Services (AWS), Google Cloud Platform (GCP), and Microsoft Azure.</div>
                        <div>For ephemeral workloads in these cloud environments, you pay only for the hours that hosts are active each month <code>metered</code>, rather than a full annual contract price per sensor <code>default</code>.</div>
                </td>
            </tr>
            <tr>
                <td colspan="1">
                    <div class="ansibleOptionAnchor" id="parameter-"></div>
                    <b>cid</b>
                    <a class="ansibleOptionLink" href="#parameter-" title="Permalink to this option"></a>
                    <div style="font-size: small">
                        <span style="color: purple">string</span>
                    </div>
                </td>
                <td>
                </td>
                <td>
                        <div>CrowdStrike Falcon Customer ID (CID).</div>
                </td>
            </tr>
            <tr>
                <td colspan="1">
                    <div class="ansibleOptionAnchor" id="parameter-"></div>
                    <b>feature</b>
                    <a class="ansibleOptionLink" href="#parameter-" title="Permalink to this option"></a>
                    <div style="font-size: small">
                        <span style="color: purple">list</span>
                         / <span style="color: purple">elements=string</span>
                    </div>
                </td>
                <td>
                        <ul style="margin: 0; padding: 0"><b>Choices:</b>
                                    <li>none</li>
                                    <li>enableLog</li>
                                    <li>disableLogBuffer</li>
                        </ul>
                </td>
                <td>
                        <div>Configure the Falcon sensor feature flags.</div>
                </td>
            </tr>
            <tr>
                <td colspan="1">
                    <div class="ansibleOptionAnchor" id="parameter-"></div>
                    <b>message_log</b>
                    <a class="ansibleOptionLink" href="#parameter-" title="Permalink to this option"></a>
                    <div style="font-size: small">
                        <span style="color: purple">string</span>
                    </div>
                </td>
                <td>
                        <ul style="margin: 0; padding: 0"><b>Choices:</b>
                                    <li>True</li>
                                    <li>true</li>
                                    <li>False</li>
                                    <li>false</li>
                        </ul>
                </td>
                <td>
                        <div>Whether or not you would like to log messages to disk.</div>
                </td>
            </tr>
            <tr>
                <td colspan="1">
                    <div class="ansibleOptionAnchor" id="parameter-"></div>
                    <b>provisioning_token</b>
                    <a class="ansibleOptionLink" href="#parameter-" title="Permalink to this option"></a>
                    <div style="font-size: small">
                        <span style="color: purple">string</span>
                    </div>
                </td>
                <td>
                </td>
                <td>
                        <div>Installation tokens prevent unauthorized hosts from being accidentally or maliciously added to your customer ID (CID).</div>
                        <div>Optional security measure for your CID.</div>
                        <div>This paramter requires supplying a <code>cid</code>.</div>
                </td>
            </tr>
            <tr>
                <td colspan="1">
                    <div class="ansibleOptionAnchor" id="parameter-"></div>
                    <b>state</b>
                    <a class="ansibleOptionLink" href="#parameter-" title="Permalink to this option"></a>
                    <div style="font-size: small">
                        <span style="color: purple">string</span>
                         / <span style="color: red">required</span>
                    </div>
                </td>
                <td>
                        <ul style="margin: 0; padding: 0"><b>Choices:</b>
                                    <li>absent</li>
                                    <li>present</li>
                        </ul>
                </td>
                <td>
                        <div>Ensures that requested parameters are removed (absent) or added (present) to the Falcon sensor.</div>
                </td>
            </tr>
            <tr>
                <td colspan="1">
                    <div class="ansibleOptionAnchor" id="parameter-"></div>
                    <b>tags</b>
                    <a class="ansibleOptionLink" href="#parameter-" title="Permalink to this option"></a>
                    <div style="font-size: small">
                        <span style="color: purple">string</span>
                    </div>
                </td>
                <td>
                </td>
                <td>
                        <div>Sensor grouping tags are optional, user-defined identifiers you can use to group and filter hosts.</div>
                        <div>To assign multiple tags, separate tags with commas.</div>
                        <div>The combined length of all tags for a host, including comma separators, cannot exceed 256 characters.</div>
                </td>
            </tr>
            <tr>
                <td colspan="1">
                    <div class="ansibleOptionAnchor" id="parameter-"></div>
                    <b>trace</b>
                    <a class="ansibleOptionLink" href="#parameter-" title="Permalink to this option"></a>
                    <div style="font-size: small">
                        <span style="color: purple">string</span>
                    </div>
                </td>
                <td>
                        <ul style="margin: 0; padding: 0"><b>Choices:</b>
                                    <li>none</li>
                                    <li>err</li>
                                    <li>warn</li>
                                    <li>info</li>
                                    <li>debug</li>
                        </ul>
                </td>
                <td>
                        <div>Configure the appropriate trace level.</div>
                </td>
            </tr>
    </table>
    <br/>




Examples
--------

.. code-block:: yaml

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
        cid: ""

    - name: Delete Agent ID to Prep Master Image
      crowdstrike.falcon.falconctl:
        state: absent
        aid: yes

    - name: Configure Falcon Sensor Proxy
      crowdstrike.falcon.falconctl:
        state: present
        apd: no
        aph: http://example.com
        app: 8080




Status
------


Authors
~~~~~~~

- Gabriel Alford (@redhatrises)
- Carlos Matos (@carlosmmatos)
