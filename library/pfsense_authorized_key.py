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
module: pfsense_authorized_key

short_description: updates ssh authorized keys for pfsense users


version_added: "2.7"

options:
  username:
    description: existing user on pfsense server
    required: true
  exclusive:

  key:
    description: can contain more than one key, don't forget to base64 encode 
    required: false

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

- name: Set Password & SSH Key
  pfsense_authorized_key:
    username: admin
    password: "{{ password }}"
    key: "{{ lookup('file', '~/.ssh/authorized_keys' ) | b64encode }}"

'''

RETURN = '''
user:
    description: dict containing data structure for webgui users
phpcode:
    description: Actual PHP Code sent to pfSense PHP Shell
'''

from ansible.module_utils.basic import AnsibleModule, to_native, to_text
from ansible.module_utils.pfsense import write_config, read_config, search, pfsense_check
from ansible.module_utils.urls import fetch_url
import base64
from collections import OrderedDict as keydict
from operator import itemgetter
import re
import shlex


# ------------------------------------------------------------------------------
# Begin code from ansible/modules/system/authorized_key.py
# ------------------------------------------------------------------------------

def parseoptions(module, options):
    '''
    reads a string containing ssh-key options
    and returns a dictionary of those options
    '''
    options_dict = keydict()  # ordered dict
    if options:
        # the following regex will split on commas while
        # ignoring those commas that fall within quotes
        regex = re.compile(r'''((?:[^,"']|"[^"]*"|'[^']*')+)''')
        parts = regex.split(options)[1:-1]
        for part in parts:
            if "=" in part:
                (key, value) = part.split("=", 1)
                options_dict[key] = value
            elif part != ",":
                options_dict[part] = None

    return options_dict


def parsekey(module, raw_key, rank=None):
    '''
    parses a key, which may or may not contain a list
    of ssh-key options at the beginning
    rank indicates the keys original ordering, so that
    it can be written out in the same order.
    '''

    VALID_SSH2_KEY_TYPES = [
        'ssh-ed25519',
        'ecdsa-sha2-nistp256',
        'ecdsa-sha2-nistp384',
        'ecdsa-sha2-nistp521',
        'ssh-dss',
        'ssh-rsa',
    ]

    options = None   # connection options
    key = None   # encrypted key string
    key_type = None   # type of ssh key
    type_index = None   # index of keytype in key string|list

    # remove comment yaml escapes
    raw_key = raw_key.replace(r'\#', '#')

    # split key safely
    lex = shlex.shlex(raw_key)
    lex.quotes = []
    lex.commenters = ''  # keep comment hashes
    lex.whitespace_split = True
    key_parts = list(lex)

    if key_parts and key_parts[0] == '#':
        # comment line, invalid line, etc.
        return (raw_key, 'skipped', None, None, rank)

    for i in range(0, len(key_parts)):
        if key_parts[i] in VALID_SSH2_KEY_TYPES:
            type_index = i
            key_type = key_parts[i]
            break

    # check for options
    if type_index is None:
        return None
    elif type_index > 0:
        options = " ".join(key_parts[:type_index])

    # parse the options (if any)
    options = parseoptions(module, options)

    # get key after the type index
    key = key_parts[(type_index + 1)]

    # set comment to everything after the key
    if len(key_parts) > (type_index + 1):
        comment = " ".join(key_parts[(type_index + 2):])

    return (key, key_type, options, comment, rank)


def parsekeys(module, lines):
    keys = {}
    for rank_index, line in enumerate(lines.splitlines(True)):
        key_data = parsekey(module, line, rank=rank_index)
        if key_data:
            # use key as identifier
            keys[key_data[0]] = key_data
        else:
            # for an invalid line, just set the line
            # dict key to the line so it will be re-output later
            keys[line] = (line, 'skipped', None, None, rank_index)
    return keys


def serialize(keys):
    lines = []
    new_keys = keys.values()
    # order the new_keys by their original ordering, via the rank item in the tuple
    ordered_new_keys = sorted(new_keys, key=itemgetter(4))

    for key in ordered_new_keys:
        try:
            (keyhash, key_type, options, comment, rank) = key

            option_str = ""
            if options:
                option_strings = []
                for option_key, value in options.items():
                    if value is None:
                        option_strings.append("%s" % option_key)
                    else:
                        option_strings.append("%s=%s" % (option_key, value))
                option_str = ",".join(option_strings)
                option_str += " "

            # comment line or invalid line, just leave it
            if not key_type:
                key_line = key

            if key_type == 'skipped':
                key_line = key[0]
            else:
                key_line = "%s%s %s %s\n" % (option_str, key_type, keyhash, comment)
        except Exception:
            key_line = key
        lines.append(key_line)
    return ''.join(lines)


def update_keys(module, params, existing_content):
    # Based on code in enforce_state() from authorized_keys.py

    user = params["user"]
    key = params["key"]
    state = params.get("state", "present")
    key_options = params.get("key_options", None)
    exclusive = params.get("exclusive", False)
    comment = params.get("comment", None)
    error_msg = "Error getting key from: %s"

    # if the key is a url, request it and use it as key source
    if key.startswith("http"):
        try:
            resp, info = fetch_url(module, key)
            if info['status'] != 200:
                module.fail_json(msg=error_msg % key)
            else:
                key = resp.read()
        except Exception:
            module.fail_json(msg=error_msg % key)

        # resp.read gives bytes on python3, convert to native string type
        key = to_native(key, errors='surrogate_or_strict')

    # extract individual keys into an array, skipping blank lines and comments
    new_keys = [s for s in key.splitlines() if s and not s.startswith('#')]

    # check current state -- just get the filename, don't create file
    do_write = False
    existing_keys = parsekeys(module, existing_content)    

    # Add a place holder for keys that should exist in the state=present and
    # exclusive=true case
    keys_to_exist = []

    # we will order any non exclusive new keys higher than all the existing keys,
    # resulting in the new keys being written to the key file after existing keys, but
    # in the order of new_keys
    max_rank_of_existing_keys = len(existing_keys)

    # Check our new keys, if any of them exist we'll continue.
    for rank_index, new_key in enumerate(new_keys):
        parsed_new_key = parsekey(module, new_key, rank=rank_index)

        if not parsed_new_key:
            module.fail_json(msg="invalid key specified: %s" % new_key)

        if key_options is not None:
            parsed_options = parseoptions(module, key_options)
            # rank here is the rank in the provided new keys, which may be unrelated to rank in existing_keys
            parsed_new_key = (parsed_new_key[0], parsed_new_key[1], parsed_options, parsed_new_key[3], parsed_new_key[4])

        if comment is not None:
            parsed_new_key = (parsed_new_key[0], parsed_new_key[1], parsed_new_key[2], comment, parsed_new_key[4])

        matched = False
        non_matching_keys = []

        if parsed_new_key[0] in existing_keys:
            # Then we check if everything (except the rank at index 4) matches, including
            # the key type and options. If not, we append this
            # existing key to the non-matching list
            # We only want it to match everything when the state
            # is present
            if parsed_new_key[:4] != existing_keys[parsed_new_key[0]][:4] and state == "present":
                non_matching_keys.append(existing_keys[parsed_new_key[0]])
            else:
                matched = True

        # handle idempotent state=present
        if state == "present":
            keys_to_exist.append(parsed_new_key[0])
            if len(non_matching_keys) > 0:
                for non_matching_key in non_matching_keys:
                    if non_matching_key[0] in existing_keys:
                        del existing_keys[non_matching_key[0]]
                        do_write = True

            # new key that didn't exist before. Where should it go in the ordering?
            if not matched:
                # We want the new key to be after existing keys if not exclusive (rank > max_rank_of_existing_keys)
                total_rank = max_rank_of_existing_keys + parsed_new_key[4]
                # replace existing key tuple with new parsed key with its total rank
                existing_keys[parsed_new_key[0]] = (parsed_new_key[0], parsed_new_key[1], parsed_new_key[2], parsed_new_key[3], total_rank)
                do_write = True

        elif state == "absent":
            if not matched:
                continue
            del existing_keys[parsed_new_key[0]]
            do_write = True

    # remove all other keys to honor exclusive
    # for 'exclusive', make sure keys are written in the order the new keys were
    if state == "present" and exclusive:
        to_remove = frozenset(existing_keys).difference(keys_to_exist)
        for key in to_remove:
            del existing_keys[key]
            do_write = True
    
    return do_write, existing_keys

# ------------------------------------------------------------------------------
# End code from ansible/modules/system/authorized_key.py
# ------------------------------------------------------------------------------



def run_module():

    module_args = dict(
        user=dict(type='str', required=True, aliases=['username']),
        exclusive=dict(type='bool', default=False),
        key=dict(type='str', required=True),
        comment=dict(type='str'),
        state=dict(type='str', default='present', choices=['absent', 'present']),
    )

    result = dict(
        changed=False,
    )

    module = AnsibleModule(
        argument_spec=module_args,
        supports_check_mode=True,
    )

    params = module.params

    configuration = ""
    
    pfsense_check(module)

    system = read_config(module, 'system')
    index = search(system['user'], 'name', params['user'])

    if index == '':
        module.fail_json(msg='username: ' + params['user'] + ' not found' )

    current_user = system['user'][index]
    base = "$config['system']['user'][{}]".format(index)
    existing_content = to_text(base64.b64decode(current_user.get('authorizedkeys', '')))

    (do_write, existing_keys) = update_keys(module, params, existing_content)
    
    if do_write:
        new_content = serialize(existing_keys)
        configuration += "{}['authorizedkeys'] = '{}';\n".format(base, base64.b64encode(new_content))

    result['phpcode'] = configuration

    if configuration != '':
        if not module.check_mode:
            write_config(module, configuration)
        result['changed'] = True

    system = read_config(module,'system')
    # result['user'] = system['user']

    module.exit_json(**result)


def main():
    run_module()


if __name__ == '__main__':
    main()
