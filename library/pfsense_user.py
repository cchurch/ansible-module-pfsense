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
module: pfsense_user

short_description: Creates a user

description: Creates a user usable by LDAP or Local Auth etc

version_added: "2.8"

options:
  name: user name
    required: true
  description:
    required: false
  priv:
    description: Privileges assigned to this user
    required: false
    possible values:
        see example below; or create a group in the GUI and export it 
        or look at the config diff in diagnostics/backup & restore/config history
author:
    - David Beveridge (@bevhost)
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
- name: create User
  pfsense_user:
    state: present
    name: beastie
    description: Beastie
    disabled: false
    expires: '02/20/2020'
    groups:
      - admins
    append: true
    priv:
      - page-dashboard-all
      - user-shell-access
    password: "{{ 'mypass' | password_hash('bcrypt') }}"
    update_password: true

- name: delete user
  pfsense_user:
    state: absent
    name: beastie

'''

RETURN = '''
user:
    description: dict containing all users
debug:
    description: Any debug messages for unexpected input types
    type: str
phpcode:
    description: Actual PHP Code sent to pfSense PHP Shell
'''

from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.pfsense import write_config, read_config, search, pfsense_check
import datetime
import json
import re


def sanitize(value):
    return "json_decode('{}')".format(json.dumps(value).replace("\\", "\\\\").replace("'", "\\'"))


def run_module():

    module_args = dict(
        name=dict(required=True, default=None, aliases=['user']),
        descr=dict(required=False, default='', aliases=['comment', 'description']),
        disabled=dict(required=False, type='bool', default=False),
        expires=dict(required=False, default=''),
        groups=dict(required=False, type='list'),
        append=dict(required=False, type='bool', default=False),
        priv=dict(required=False, type='list', aliases=['privs', 'privileges']),
        password=dict(required=False, no_log=True),
        update_password=dict(required=False, type='bool', default=False),
        set_initial_password=dict(required=False, type='bool', default=True),
        state=dict(required=False, default='present', choices=['present', 'absent']),
    )

    result = dict(
        changed=False,
    )

    module = AnsibleModule(
        argument_spec=module_args,
        supports_check_mode=True
    )

    params = module.params
    configuration = ""

    pfsense_check(module)

    system = read_config(module, 'system')
    index = search(system['user'], 'name', params['name'])
    if index == '':
        current_user = {}
    else:
        current_user = system['user'][index]
    base = "$config['system']['user'][{}]".format(index)

    if params['state'] == 'present':

        # Determine whether creating a new user or updating an existing one.
        if index == '':
            uid = system['nextuid']
            configuration += "$config['system']['nextuid']++;\n"
            configuration += "$user = array();\n"
            configuration += "$user['uid'] = {};\n".format(sanitize(uid))
            configuration += "$user['scope'] = 'user';\n"
            dest = '$user'
        else:
            uid = current_user['uid']
            dest = base

        # Validate format of expires parameter if given: MM/DD/YYYY
        if params['expires']:
            try:
                datetime.datetime.strptime(params['expires'],'%m/%d/%Y')
            except ValueError:
                module.fail_json(msg='Invalid date for expires; must be MM/DD/YYYY.')

        # Update scalar parameters on user.
        for param in ('name', 'descr', 'expires'):
            if current_user.get(param) != params[param]:
                configuration += "{}['{}'] = {};\n".format(dest, param, sanitize(params[param]))

        # Set/remove disabled key on user.
        if params['disabled'] and 'disabled' not in current_user:
            configuration += "{}['disabled'] = '';\n".format(dest)
        elif not params['disabled'] and 'disabled' in current_user:
            configuration += "unset({}['disabled']);\n".format(dest)

        # Validate password format (bcrypt hash) and update password.
        if params['password'] and (index == '' or params['update_password']):
            if not re.match(r'^\$2[abxy]??\$\d+?\$[A-Za-z0-9./]{22,}$', params['password']):
                module.fail_json(msg='Password must be provided as a bcrypt hash.')
            if current_user.get('bcrypt-hash') != params['password']:
                configuration += "{}['bcrypt-hash'] = {};\n".format(dest, sanitize(params['password']))
        # Set an initial password for a user if no password is set; store the
        # password in ~/initial-password so it can be retrieved via SSH.
        elif params['set_initial_password'] and not current_user.get('bcrypt-hash'):
            configuration += "$initial_password_path = '/home/' . {}['name'] . '/initial-password';".format(dest)
            configuration += "if (file_exists($initial_password_path)) {\n";
            configuration += "  $initial_password = file_get_contents($initial_password_path);\n"
            configuration += "}\n"
            configuration += "if (empty($initial_password)) {\n";
            configuration += "  $initial_password = implode(array_map(function($c) { return chr(ord($c) % 92 + 33); }, str_split(openssl_random_pseudo_bytes(15))));\n"
            configuration += "}\n"
            configuration += "local_user_set_password({}, $initial_password);\n".format(dest)
            configuration += "@mkdir(dirname($initial_password_path), 0755, true);\n"
            configuration += "@file_put_contents($initial_password_path, $initial_password);\n"
            configuration += "@chmod($initial_password_path, 0700);\n"
            configuration += "@chgrp($initial_password_path, 'nobody');\n"
            configuration += "@chown($initial_password_path, {});\n".format(uid)

        # Update user privileges. FIXME: Validate privilege names!
        if current_user.get('priv') != params['priv']:
            if params['priv']:
                configuration += "{}['priv'] = {};\n".format(dest, sanitize(params['priv']))
            else:
                configuration += "unset({}['priv']);\n".format(dest)

        # If creating a new user, append user array to config.
        if index == '':
            configuration += "{} = {};\n".format(base, dest)

        # Apply local user changes.
        if configuration:
            configuration += "local_user_set({});\n".format(dest)

        # Validate group names.
        group_names = params['groups'] or []
        for group_name in group_names:
            group_index = search(system['group'], 'name', group_name)
            if group_index == '':
                module.fail_json(msg='Group "{}" not found'.format(group_name))

        # Update user group membership.
        for group_index, group in enumerate(system['group']):
            if group['name'] == 'all':
                continue
            # Add user to specified groups where not already a member.
            if uid not in group.get('member', []) and group['name'] in group_names:
                configuration += "$config['system']['group'][{}]['member'][] = {};\n".format(group_index, sanitize(uid))
                configuration += "local_group_set($config['system']['group'][{}]);\n".format(group_index)
            # Remove user from any other groups when append is False.
            if uid in group.get('member', []) and group['name'] not in group_names and not params['append']:
                group_members = [x for x in group.get('member', []) if x != uid]
                configuration += "$config['system']['group'][{}]['member'] = {};\n".format(group_index, sanitize(group_members))
                configuration += "local_group_set($config['system']['group'][{}]);\n".format(group_index)

    elif params['state'] == 'absent':
        if index != '':
            configuration += "local_user_del({});\n".format(base)
            configuration += "unset({});\n".format(base)
    else:
        module.fail_json(msg='Incorrect state value, possible choices: absent, present(default)')

    if configuration:
        configuration = "include_once('auth.inc');\n" + configuration

    result['phpcode'] = configuration

    if module.check_mode:
        module.exit_json(**result)

    if configuration != '':
        write_config(module, configuration)
        result['changed'] = True

    system = read_config(module, 'system')
    for user in system['user']:
        user.pop('bcrypt-hash', None)
    result['user'] = system['user']
    result['group'] = system['group']

    module.exit_json(**result)


def main():
    run_module()


if __name__ == '__main__':
    main()
