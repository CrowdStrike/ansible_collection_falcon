# redhat_insights_yara.yml

Downloads CrowdStrike YARA hunting rules and deploys them to RHEL systems running Red Hat Insights Client. This playbook:

- Downloads YARA rules for Linux to localhost (one time)
- Distributes the rules to all hosts in the `yara` host group
- Unpacks rules into the third-party signatures directory used by Red Hat Insights Client
