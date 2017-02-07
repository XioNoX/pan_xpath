#!/usr/bin/python
# -*- coding: utf-8 -*-


DOCUMENTATION = '''
---
module: pan_xpath
author: "Arzhel Younsi"
version_added: "2.2"
short_description: "Loads XML into PAN devices."
description:
    - "Loads XML into PAN devices."
requirements:
    - urllib2
    - urllib
    - ssl
    - xml
options:
    hostname:
        description:
          - IP or FQDN of the device you want to connect to.
        required: True
    api_key:
        description:
          - PAN API key.
        required: True
    xml_file:
        description:
          - Source XML file
        required: True
    file_xpath:
        description:
          - Xpath to load on the file side.
        required: True
    device_xpath:
        description:
          - Xpath to which push the loaded config.
        required: True
    configuration:
        description:
          - Work on active or candidate configuration
        required: False
        default: candidate
        choices: [active, candidate]
'''

EXAMPLES = '''
    - name: "[Panorama] Push services"
      pan_xpath:
        hostname: "{{ inventory_hostname }}"
        api_key: "{{ pan_api_key }}"
        xml_file: "build/{{ inventory_hostname }}/tmp/PAN-Office-Firewalls.xml"
        file_xpath: ".//devices/entry/vsys/entry/service"
        configuration: "candidate"
        device_xpath: "/config/devices/entry/device-group/entry[@name='xionox-test']/service"
        diff_file: "{{ logs_dir }}/{{ inventory_hostname }}-services.diff"
      register: push_services
'''

RETURN = '''
    changed:
        description: If there is a difference between the device and the local copy
        returned: always
        type: bool
        sample: True
    diff:
        description: diff of the change
        returned: if existing diff
        type: string
        sample: "- <entry name="service-aruba-mgmt-tcp--foo">\n+ <entry name="service-aruba-mgmt-tcp">\n- <port>22,443</port>\n+ <port>22, 443, 4343</port>"
    msg:
        description: Message returned from the device
        returned: When a configuration change is done
        type: string
        sample: "command succeeded"

'''


import urllib2, urllib, ssl, difflib
from xml.etree import ElementTree as etree



def main():
    module = AnsibleModule(
        argument_spec=dict(
            hostname=dict(type='str', required=True),
            api_key=dict(type='str', required=True, no_log=True),
            xml_file=dict(type='str', required=True),
            file_xpath=dict(type='str', required=True),
            device_xpath=dict(type='str', required=True),
            diff_file=dict(type='str', required=False, default=None),
            configuration=dict(type='str', required=False, default="candidate", choices=['candidate', 'active']),
            ),
        supports_check_mode=True
    )


    hostname = module.params['hostname']
    api_key = module.params['api_key']
    xml_file = module.params['xml_file']
    file_xpath = module.params['file_xpath']
    device_xpath = module.params['device_xpath']
    diff_file = module.params['diff_file']
    configuration = module.params['configuration']

    results = {}
    url = "https://" + hostname + "/api/"

    ssl_no_verify = ssl.create_default_context()
    ssl_no_verify.check_hostname = False
    ssl_no_verify.verify_mode = ssl.CERT_NONE

    # Parse the XML file
    parsed_xml_file = etree.parse(xml_file)

    # Select the part needed
    file_subtree = parsed_xml_file.find(file_xpath)

    # Convert selected part to string, or fail if missing.
    if file_subtree is not None:
        file_subtree_str = etree.tostring(file_subtree, method="xml").strip()
    else:
        module.fail_json(msg="Can't find " + file_xpath + " in " + xml_file)

    # Prepare the query to get the current configuration (active or candidate)
    if configuration == 'active':
        action = 'show'
    else:
        action = 'get'
    values = {"type":"config", "key":api_key, "action":action, "xpath":device_xpath }
    req = urllib2.Request(url, urllib.urlencode(values))
    try:
        pan_response_diff = urllib2.urlopen(req, context=ssl_no_verify)
    except Exception, e:
        module.fail_json(msg="cannot connect to device: " + str(e))

    pan_response_diff = etree.fromstring(pan_response_diff.read())
    reply_result_diff = pan_response_diff.find(".//result/")

    # If tree section doesn't exist, it can mean the user did a typo
    # OR it's the first time something is pushed there
    # We assume for latter, and will let the device send a failure
    # If the sent data doesn't match what the device expects
    if reply_result_diff is not None:
        # Remove unneeded attributes from the reply (to remove diff noise)
        for elem in reply_result_diff.iter():
            if elem.attrib.get('admin'): elem.attrib.pop("admin")
            if elem.attrib.get('dirtyId'): elem.attrib.pop("dirtyId")
            if elem.attrib.get('time'): elem.attrib.pop("time")
        # Convert reply back to a string
        select_reply = etree.tostring(reply_result_diff, method="xml").strip()
        # remove white spaces from beginning and end as well as new line on each array items (lines)
        select_reply_strip = [x.strip() for x in select_reply.split('\n')]
        file_subtree_str_strip = [x.strip() for x in file_subtree_str.split('\n')]
        # Then diff the two
        d = difflib.Differ()
        result = list(d.compare(select_reply_strip, file_subtree_str_strip))
        changed = False
        changed_lines = []
        # Verify if there is a change in the diff
        for diffline in result:
            if not diffline.startswith("  "):
                changed = True
                changed_lines.append(diffline)
        newline = '\n'
        changed_str = newline.join(changed_lines)
        results['diff'] = changed_str
        # If diff_file and a change, write the change to the file
        if diff_file and changed:
            f = open(diff_file, 'w')
            f.write(changed_str)
            f.close()
    else:
        changed = True
        if diff_file:
            f = open(diff_file, 'w')
            f.write(file_subtree_str)
            f.close()

    if not module.check_mode and changed == True:
        # Prepare the values to be pushed to the device
        values = {"type":"config", "key":api_key, "action":"edit", "xpath":device_xpath, "element":file_subtree_str}
        req = urllib2.Request(url, urllib.urlencode(values))
        try:
            pan_response_push = urllib2.urlopen(req, context=ssl_no_verify)
        except Exception, e:
            module.fail_json(msg="cannot connect to device: " + str(e))
        element_root = etree.fromstring(pan_response_push.read())
        pan_msg = etree.tostring(element_root.find(".//msg"),method="xml")
        results['pan_msg'] = pan_msg

        api_code = element_root.attrib.get('code')
        api_status = element_root.attrib.get('status')
        # https://www.paloaltonetworks.com/documentation/71/pan-os/xml-api/pan-os-xml-api-error-codes
        if api_code not in ['19', '20']:
            module.fail_json(msg=api_status + " " + pan_msg)

    results['changed'] = changed

    module.exit_json(**results)



# standard ansible module imports
from ansible.module_utils.basic import *

if __name__ == '__main__':
    main()
