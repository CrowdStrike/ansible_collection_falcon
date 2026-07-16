#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2025, CrowdStrike Inc.
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

DOCUMENTATION = r"""
---
module: ngsiem_parser

short_description: Manage NG-SIEM parsers

version_added: "4.13.0"

description:
  - Create, update, clone, and delete custom NG-SIEM parsers in the CrowdStrike
    Falcon platform.
  - Parsers transform raw log data into normalized events for Next-Gen SIEM.
  - Custom parsers are managed through LogScale YAML templates. Provide the full
    template via I(parser_yaml) for create and update operations.
  - Supports idempotent operations that only make changes when the meaningful
    parser content differs from what is already stored.
  - Use M(crowdstrike.falcon.ngsiem_parser_info) to discover existing parsers and
    retrieve their definitions.

options:
  state:
    description:
      - The desired state of the parser.
      - C(present) ensures the parser exists with the specified content.
      - C(absent) ensures the parser does not exist.
    type: str
    choices: ["present", "absent"]
    default: present
  repository:
    description:
      - The name of the repository the parser belongs to.
    type: str
    default: parsers-repository
  name:
    description:
      - The name of the parser.
      - Required when creating a new parser and when using I(clone_from) or
        I(extension_of).
      - Used to look up an existing parser when I(parser_id) is not provided.
    type: str
    required: false
  parser_id:
    description:
      - The version-suffixed ID of an existing parser (e.g. C(abc123:1.0.0)).
      - Preferred for identifying an existing parser during update or delete.
      - When provided with I(state=absent), the parser is deleted by ID.
    type: str
    required: false
  parser_yaml:
    description:
      - The full LogScale parser YAML template.
      - Required when creating or updating a parser via I(state=present) unless
        I(clone_from) or I(extension_of) is used.
      - For idempotency, the module compares the C(script), C(tagFields), and
        C(testCases) of this template against the stored parser and only updates
        when they differ.
    type: str
    required: false
  clone_from:
    description:
      - The ID of a source parser to clone into a new parser named I(name).
      - Mutually exclusive with I(parser_yaml) and I(extension_of).
      - Only applies when the target parser (I(name)) does not already exist.
    type: str
    required: false
  extension_of:
    description:
      - The unversioned base parser ID to create an extension of, named I(name).
      - "B(Note:) The base parser ID must be B(unversioned) (no C(:x.y.z) suffix)."
      - Mutually exclusive with I(parser_yaml) and I(clone_from).
      - Only applies when the target parser (I(name)) does not already exist.
    type: str
    required: false

extends_documentation_fragment:
  - crowdstrike.falcon.credentials
  - crowdstrike.falcon.credentials.auth

notes:
  - B(Idempotency:) For I(state=present) with I(parser_yaml), the module fetches
    the current parser template and compares C(script), C(tagFields), and
    C(testCases) semantically (ignoring whitespace and the auto-incremented
    version). Perfect round-trip idempotency is not guaranteed because the server
    normalizes stored scripts; a re-run may report a change if the server
    reformats content.
  - B(Versioning:) Custom parsers auto-increment their version on each update or
    clone. The returned parser ID is version-suffixed and will differ from the
    input ID after an update.
  - B(Parser Lookup:) When I(parser_id) is not provided, the module searches by
    exact I(name). Prefer I(parser_id) for precise targeting.
  - B(State Management:) For I(state=absent), if the parser is not found, the
    module exits successfully without making any changes (idempotent). A stale
    index entry that 404s on delete is treated as already absent.
  - B(Check mode:) In check mode the module reports the intended change without
    mutating the parser.

requirements:
  - NGSIEM Parsers [B(READ), B(WRITE)] API scope
  - CrowdStrike FalconPy >= 1.6.3

author:
  - Carlos Matos (@carlosmmatos)
"""

EXAMPLES = r"""
- name: Create a custom parser from a YAML template
  crowdstrike.falcon.ngsiem_parser:
    name: my-custom-parser
    parser_yaml: "{{ lookup('file', 'my-parser.yaml') }}"

- name: Update a parser (idempotent - only changes when content differs)
  crowdstrike.falcon.ngsiem_parser:
    name: my-custom-parser
    parser_yaml: "{{ lookup('file', 'my-parser-v2.yaml') }}"

- name: Clone an existing parser into a new one
  crowdstrike.falcon.ngsiem_parser:
    name: my-cloned-parser
    clone_from: "10f55deaa2893f60b87af305f44f80bf:1.0.0"

- name: Create an extension of a base parser (base ID must be unversioned)
  crowdstrike.falcon.ngsiem_parser:
    name: my-parser-extension
    extension_of: "10f55deaa2893f60b87af305f44f80bf"

- name: Delete a parser by name
  crowdstrike.falcon.ngsiem_parser:
    name: my-custom-parser
    state: absent

- name: Delete a parser by ID
  crowdstrike.falcon.ngsiem_parser:
    parser_id: "10f55deaa2893f60b87af305f44f80bf:1.1.0"
    state: absent
"""

RETURN = r"""
parser:
  description:
    - Information about the parser that was created, updated, or cloned.
  type: dict
  returned: when state=present and a parser exists
  contains:
    id:
      description: The version-suffixed unique identifier of the parser.
      type: str
      returned: success
      sample: "10f55deaa2893f60b87af305f44f80bf:1.1.0"
    name:
      description: The name of the parser.
      type: str
      returned: success
      sample: "my-custom-parser"
    script:
      description: The LogScale/CQL parsing script.
      type: str
      returned: success
    fields_to_tag:
      description: The list of fields to tag on parsed events.
      type: list
      returned: success
    test_cases:
      description: The list of test cases associated with the parser.
      type: list
      returned: success
"""

import traceback

from ansible.module_utils.basic import AnsibleModule, missing_required_lib
from ansible_collections.crowdstrike.falcon.plugins.module_utils.common_args import (
    falconpy_arg_spec,
)
from ansible_collections.crowdstrike.falcon.plugins.module_utils.falconpy_utils import (
    authenticate,
    check_falconpy_version,
    handle_return_errors,
)

FALCONPY_IMPORT_ERROR = None
try:
    from falconpy import NGSIEM

    HAS_FALCONPY = True
except ImportError:
    HAS_FALCONPY = False
    FALCONPY_IMPORT_ERROR = traceback.format_exc()

YAML_IMPORT_ERROR = None
try:
    import yaml

    HAS_YAML = True
except ImportError:
    HAS_YAML = False
    YAML_IMPORT_ERROR = traceback.format_exc()

# The parser modules require the typed clone/extension methods added in 1.6.3.
MINIMUM_FALCONPY_VERSION = "1.6.3"

NGSIEM_PARSER_ARGS = {
    "state": {"type": "str", "choices": ["present", "absent"], "default": "present"},
    "repository": {"type": "str", "default": "parsers-repository"},
    "name": {"type": "str", "required": False},
    "parser_id": {"type": "str", "required": False},
    "parser_yaml": {"type": "str", "required": False},
    "clone_from": {"type": "str", "required": False},
    "extension_of": {"type": "str", "required": False},
}


def argspec():
    """Define the module's argument spec."""
    args = falconpy_arg_spec()
    args.update(NGSIEM_PARSER_ARGS)

    return args


def validate_params(module):
    """Validate module parameters."""
    state = module.params["state"]
    name = module.params.get("name")
    parser_id = module.params.get("parser_id")

    if not name and not parser_id:
        module.fail_json(msg="Either 'name' or 'parser_id' is required")

    if state == "present":
        creation_inputs = [
            module.params.get("parser_yaml"),
            module.params.get("clone_from"),
            module.params.get("extension_of"),
        ]
        provided = [i for i in creation_inputs if i]
        if len(provided) > 1:
            module.fail_json(
                msg="'parser_yaml', 'clone_from', and 'extension_of' are mutually exclusive"
            )

        if (module.params.get("clone_from") or module.params.get("extension_of")) and not name:
            module.fail_json(
                msg="'name' is required when using 'clone_from' or 'extension_of'"
            )


def find_parser_by_name(falcon, module, name):
    """Find a parser by exact name via the substring filter, then exact match."""
    result = falcon.list_parsers(
        repository=module.params["repository"],
        filter=f"name:~'{name}'",
        limit=100,
    )
    if result["status_code"] == 200 and result["body"].get("resources"):
        for item in result["body"]["resources"]:
            if item.get("Name") == name:
                return item
    return None


def get_parser_by_id(falcon, module, parser_id):
    """Get a parser summary by ID from the list endpoint."""
    result = falcon.list_parsers(
        repository=module.params["repository"],
        limit=500,
    )
    if result["status_code"] == 200 and result["body"].get("resources"):
        for item in result["body"]["resources"]:
            if item.get("ID") == parser_id:
                return item
    return None


def resolve_existing(falcon, module):
    """Resolve the current parser (summary dict) by parser_id or name."""
    parser_id = module.params.get("parser_id")
    name = module.params.get("name")

    if parser_id:
        return get_parser_by_id(falcon, module, parser_id)
    if name:
        return find_parser_by_name(falcon, module, name)
    return None


def get_template_yaml(falcon, module, parser_id):
    """Fetch the stored YAML template for a parser ID."""
    result = falcon.get_parser_template(
        ids=parser_id, repository=module.params["repository"]
    )
    if result["status_code"] == 200 and result["body"].get("resources"):
        return result["body"]["resources"][0].get("yaml_template")
    return None


def _semantic_content(yaml_text):
    """Extract the meaningful, comparable content from a parser YAML template.

    Returns a normalized tuple of (script, tagFields, testCases) with whitespace
    stripped from the script. The auto-incremented version and schema/name are
    intentionally excluded so idempotency keys on the actual parser logic.
    """
    parsed = yaml.safe_load(yaml_text) or {}
    script = (parsed.get("script") or "").strip()
    tag_fields = parsed.get("tagFields") or []
    test_cases = parsed.get("testCases") or []
    return script, tag_fields, test_cases


def parser_needs_update(current_yaml, desired_yaml):
    """Compare stored vs desired YAML on script + tagFields + testCases."""
    if not current_yaml:
        return True
    return _semantic_content(current_yaml) != _semantic_content(desired_yaml)


def _extract_parser_id(body):
    """Pull a parser ID out of a create/clone/update response body.

    Clone returns ``resources`` as a dict ``{id, name}``; the template methods
    return a list. Handle both shapes.
    """
    resources = body.get("resources")
    if isinstance(resources, dict):
        return resources.get("id")
    if isinstance(resources, list) and resources:
        first = resources[0]
        if isinstance(first, dict):
            return first.get("id")
        return first
    return None


def build_parser_result(falcon, module, parser_id):
    """Build the returned parser dict from the full definition."""
    result = falcon.get_parser(ids=parser_id, repository=module.params["repository"])
    if result["status_code"] == 200 and result["body"].get("resources"):
        return result["body"]["resources"][0]
    return {"id": parser_id}


def create_from_template(falcon, module):
    """Create a new parser from the provided YAML template."""
    return falcon.create_parser_from_template(
        repository=module.params["repository"],
        name=module.params["name"],
        yaml_template=module.params["parser_yaml"],
    )


def update_from_template(falcon, module, parser_id):
    """Update an existing parser from the provided YAML template."""
    return falcon.update_parser_from_template(
        ids=parser_id,
        repository=module.params["repository"],
        yaml_template=module.params["parser_yaml"],
    )


def clone_parser(falcon, module):
    """Clone a source parser into a new parser named 'name'."""
    return falcon.clone_parser(
        source_id=module.params["clone_from"],
        new_name=module.params["name"],
    )


def create_extension(falcon, module):
    """Create an extension of a base parser."""
    return falcon.create_parser_extension(
        base_parser_id=module.params["extension_of"],
        extension_name=module.params["name"],
    )


def handle_present(falcon, module, result):
    """Handle state=present (create, update, clone, or extension)."""
    current = resolve_existing(falcon, module)

    if module.params.get("parser_id") and not current:
        module.fail_json(
            msg=f"Parser with ID '{module.params['parser_id']}' not found"
        )

    if current:
        current_id = current.get("ID") or current.get("id")

        # Clone/extension only apply when creating a new parser; an existing
        # parser with the target name is left as-is for those inputs.
        if module.params.get("parser_yaml"):
            current_yaml = get_template_yaml(falcon, module, current_id)
            if parser_needs_update(current_yaml, module.params["parser_yaml"]):
                if module.check_mode:
                    result["changed"] = True
                    result["parser"] = current
                    return
                update_result = update_from_template(falcon, module, current_id)
                if update_result["status_code"] not in (200, 201):
                    handle_return_errors(module, result, update_result)
                result["changed"] = True
                new_id = _extract_parser_id(update_result["body"]) or current_id
                result["parser"] = build_parser_result(falcon, module, new_id)
                return

        result["parser"] = build_parser_result(falcon, module, current_id)
        return

    # No existing parser - create it.
    if module.check_mode:
        result["changed"] = True
        return

    if module.params.get("clone_from"):
        create_result = clone_parser(falcon, module)
    elif module.params.get("extension_of"):
        create_result = create_extension(falcon, module)
    elif module.params.get("parser_yaml"):
        create_result = create_from_template(falcon, module)
    else:
        module.fail_json(
            msg="One of 'parser_yaml', 'clone_from', or 'extension_of' is "
            "required to create a parser"
        )
        return

    if create_result["status_code"] not in (200, 201):
        handle_return_errors(module, result, create_result)

    new_id = _extract_parser_id(create_result["body"])
    if new_id:
        result["changed"] = True
        result["parser"] = build_parser_result(falcon, module, new_id)


def handle_absent(falcon, module, result):
    """Handle state=absent (delete)."""
    current = resolve_existing(falcon, module)

    if not current:
        return

    parser_id = current.get("ID") or current.get("id")

    if module.check_mode:
        result["changed"] = True
        return

    delete_result = falcon.delete_parser(
        ids=parser_id, repository=module.params["repository"]
    )
    status = delete_result["status_code"]
    if status == 404:
        # Stale index entry - treat as already absent (idempotent).
        return
    if status not in (200, 202):
        handle_return_errors(module, result, delete_result)
    result["changed"] = True


def main():
    """Entry point for module execution."""
    module = AnsibleModule(
        argument_spec=argspec(),
        supports_check_mode=True,
    )

    if not HAS_FALCONPY:
        module.fail_json(
            msg=missing_required_lib("falconpy"), exception=FALCONPY_IMPORT_ERROR
        )

    if not HAS_YAML:
        module.fail_json(
            msg=missing_required_lib("PyYAML"), exception=YAML_IMPORT_ERROR
        )

    check_falconpy_version(module, minimum_version=MINIMUM_FALCONPY_VERSION)
    validate_params(module)

    result = dict(
        changed=False,
    )

    falcon = authenticate(module, NGSIEM)

    try:
        if module.params["state"] == "present":
            handle_present(falcon, module, result)
        else:
            handle_absent(falcon, module, result)
    except Exception as e:
        module.fail_json(
            msg=f"An error occurred while managing the parser: {str(e)}",
            **result,
        )

    module.exit_json(**result)


if __name__ == "__main__":
    main()
