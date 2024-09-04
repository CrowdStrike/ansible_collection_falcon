# -*- coding: utf-8 -*-

# Copyright: (c) 2023, CrowdStrike Inc.
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type


class ModuleDocFragment(object):
    """Module doc fragment for credentials"""

    # Plugin options for common _info modules
    DOCUMENTATION = r"""
options:
  filter:
    description:
      - The filter expression that should be used to limit the results using FQL (Falcon Query Language) syntax.
      - See the return values or CrowdStrike docs for more information about the available filters that can be used.
    type: str
"""
    # Not all endpoints will have a sort option
    SORT = r"""
options:
  sort:
    description:
      - The property to sort by in FQL (Falcon Query Language) syntax.
      - See the L(FalconPy documentation,https://www.falconpy.io/Usage/Falcon-Query-Language.html#using-fql-in-a-sort)
        for more information about sorting with FQL.
    type: str
"""
    # Probably to be discontinued
    PAGINATION = r"""
  limit:
    description:
      - The maximum number of records to return. [1-5000]
      - Use with the offset parameter to manage pagination of results.
    type: int
  offset:
    description:
      - The offset to start retrieving records from.
    type: int
"""
