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
module: pfsense_config

short_description: Loads RAW router configs into FRR

description:
  - This module has been tested with BGP only at this time (April 2019).
    Other routing protocols should load into the configuration but will most likely need to be activated in the GUI.

version_added: "2.7"

options:
  option:
    bgpd:
      - base64 encoded router configuration

author:
    - David Beveridge (@bevhost)

notes:
Ansible is located in an different place on BSD systems such as pfsense.
You can create a symlink to the usual location like this

ansible -m raw -a "/bin/ln -s /usr/local/bin/python2.7 /usr/bin/python" -k -u root mybsdhost1

Alternatively, you could use an inventory variable

[fpsense:vars]
ansible_python_interpreter=/usr/local/bin/python2.7

'''

EXAMPLES = '''

# create the file (e.g. with a template) then...

- name: Load RAW BGP configuration 
  pfsense_frr_raw:
    bgpd: "{{ lookup('file', 'path/to/config/file' ) | b64encode }}"

'''

RETURN = '''
'''

from ansible.module_utils.basic import AnsibleModule
import json
import platform
import os

cmd = "/usr/local/sbin/pfSsh.php"

def write_config(module,configuration):

    php = configuration+'\nexec\nexit\n'

    rc, out, err = module.run_command(cmd,data=php)
    if rc != 0:
        module.fail_json(msg='error writing config',error=err, output=out)


def read_config(module,section):

    php = 'echo "\n".json_encode($config["'+section+'"])."\n";\nexec\nexit\n'

    rc, out, err = module.run_command(cmd,data=php)
    if rc != 0:
        module.fail_json(msg='error reading config',error=err, output=out)

    start = "\npfSense shell: exec\n"
    end = "\npfSense shell: exit\n"
    try:
        s = out.index(start) + len(start)
        e = out.index(end)
        return json.loads(out[s:e])
    except:
        module.fail_json(msg='error converting to JSON', json=out[s:e])


def run_module():

    module_args = dict(
        state=dict(required=False,default='present',choices=['present','absent']),
        zebra=dict(required=False),
        bgpd=dict(required=False),
        ospfd=dict(required=False),
        ospf6d=dict(required=False)
    )

    args = ['zebra','bgpd','ospfd','ospf6d']

    result = dict(
        changed=False,
    )

    module = AnsibleModule(
        argument_spec=module_args,
        required_one_of=[args],
        supports_check_mode=True
    )

    params = module.params

    configuration = ""

    # Make sure we're actually targeting a pfSense firewall
    if not os.path.isfile(cmd):
        module.fail_json(msg='pfSense shell not found at '+cmd)
    if platform.system() != "FreeBSD":
        module.fail_json(msg='pfSense platform expected: FreeBSD found: '+platform.system())
    if not os.path.isfile('/usr/local/pkg/frr.inc'):
        module.fail_json(msg='pfsense-pkg-frr package not installed')

    index=0
    cfg = read_config(module,'installedpackages')
    try:
        frr = cfg['frrglobalraw']['config'][0]
    except:
        index = ""

    base = "$config['installedpackages']['frrglobalraw']['config'][0]"
    if params['state'] == 'present':
        for p in args:
            if type(params[p]) in [str,unicode]:
                if index=="" or (p in frr and params[p] != frr[p]):
                    configuration += base + "['"+p+"']='" + params[p] + "';\n"
    elif params['state'] == 'absent':
        if index != '':
            configuration += "unset("+base+");\n"
    else:
        module.fail_json(msg='Incorrect state value, possible choices: absent, present(default)')


    result['phpcode'] = configuration

    if module.check_mode:
        module.exit_json(**result)
    if configuration != '':
        # uncomment these to overwrite gui config
        configuration += "unset($config['installedpackages']['frr']);\n"
        configuration += "unset($config['installedpackages']['frrbgp']);\n"
        configuration += "$frr['enable']='on';\n";
        configuration += "$config['installedpackages']['frrbgp']['config']=$frr;\n";
        configuration += "$frr['password']=uniqid();\n";
        configuration += "$config['installedpackages']['frr']['config']=$frr;\n"
        # Write new config
        configuration += "write_config();\n;"
        # Apply the config
        configuration += "include('/usr/local/pkg/frr.inc');frr_generate_config();\n"
        write_config(module,configuration)
        result['changed'] = True

    module.exit_json(**result)

def main():
    run_module()

if __name__ == '__main__':
    main()




