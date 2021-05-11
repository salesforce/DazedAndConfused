#
# Copyright (c) 2021, salesforce.com, inc.
# All rights reserved.
# SPDX-License-Identifier: BSD-3-Clause
# For full license text, see the LICENSE file in the repo root or https://opensource.org/licenses/BSD-3-Clause
#
###
#Checks bower.json files for potential and active dependency confusion attacks###
import urllib
import json
import re

DEPLIST = ['dependencies', 'devDependencies', 'peerDependencies', 'bundledDependencies', 'bundleDependencies', 'optionalDependencies']

#grabs actual dependencies from an npm json manifest file
def get_bower_dependencies(filename, json_file):
    result = []
    try:
        data = json.loads(json_file)
        checklist = []
        #dependencies come in all these object forms
        for key in data:
            if key in DEPLIST:
                for dep in data[key]:
                    result.append({'name': dep, 'version': data[key][dep].replace('^', '')})
    except Exception as e:
        #print(f"Bower Error: {e}")
        raise
    return result

#checks the npm public repo for a package
def check_bower_public_repo(pkg, registryurl=None):
    try:
        base_url = 'https://registry.npmjs.org/'
        if registryurl:
            base_url = registryurl

        with urllib.request.urlopen(f"{base_url}{pkg['name']}/", timeout=10) as url:
            data = json.loads(url.read().decode())
        if "dist-tags" in data:
            return data['dist-tags']['latest']
        else:
            return data['time']['unpublished']['versions'][0]
    except Exception as e:
        #print(f"Bower Error: {e}")
        return '0.0.0.0'
