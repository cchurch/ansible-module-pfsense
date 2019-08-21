#!/usr/bin/python
# vim: set expandtab:

# Copyright: (c) 2018, David Beveridge <dave@bevhost.com>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

ANSIBLE_METADATA = {
    'metadata_version': '1.1',
    'status': ['preview'],
    'supported_by': 'community'
}

DOCUMENTATION = '''
---
module: pfsense_facts

short_description: Return facts from a pfSense system

description: Return all or part of the configuration from pfSense.

version_added: "2.8"

options:
  section: configuration section to return (all returns everything).
author:
    - Chris Church (@cchurch)

notes:
Ansible is located in an different place on BSD systems such as pfsense.
You can create a symlink to the usual location like this

ansible -m raw -a "/bin/ln -s /usr/local/bin/python2.7 /usr/bin/python" -k -u root mybsdhost1

Alternatively, you could use an inventory variable

[fpsense:vars]
ansible_python_interpreter=/usr/local/bin/python2.7

'''

EXAMPLES = '''
- name: get facts
  pfsense_facts:
    section: all
'''

RETURN = '''
ansible_facts:
    pfsense:
        description: dict containing pfsense config
'''

from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.pfsense import read_config, pfsense_check


def run_module():

    module_args = dict(
        section=dict(required=False, default='all'),
    )

    result = dict(
        changed=False,
        ansible_facts=dict(pfsense=dict()),
    )

    module = AnsibleModule(
        argument_spec=module_args,
        supports_check_mode=True
    )

    params = module.params

    pfsense_check(module)

    if params['section'] == 'all':
        config = read_config(module)
        result['ansible_facts']['pfsense'].update(config)
    else:
        section_config = read_config(module, params['section'])
        result['ansible_facts']['pfsense'][params['section']] = section_config

    # FIXME: Filter out private keys, etc.

    module.exit_json(**result)


def main():
    run_module()


if __name__ == '__main__':
    main()
