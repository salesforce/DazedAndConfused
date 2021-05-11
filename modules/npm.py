#
# Copyright (c) 2021, salesforce.com, inc.
# All rights reserved.
# SPDX-License-Identifier: BSD-3-Clause
# For full license text, see the LICENSE file in the repo root or https://opensource.org/licenses/BSD-3-Clause
#
###
#Checks NPM files for potential and active dependency confusion attacks
###
import dac_constants
import urllib
import json
import re
from urllib.parse import urlparse

DEPLIST = ['dependencies', 'devDependencies', 'peerDependencies', 'bundledDependencies', 'bundleDependencies', 'optionalDependencies']

#grabs actual dependencies from an npm json manifest file
def get_npm_dependencies(filename, json_file):
    result = []
    try:
        if filename.lower() == "package.json":
            data = json.loads(json_file)
            checklist = []
            #dependencies come in all these object forms
            for key in data:
                if key in DEPLIST:
                    for dep in data[key]:
                        version = "TBD"
                        if isinstance(data[key], dict):
                            version = data[key][dep].replace('^', '')
                        if not dep.startswith('@'):
                            result.append({'name': dep, 'version': version})
        elif filename.lower() == "package-lock.json" or filename.lower() == "npm-shrinkwrap.json":
            #try to clean it up, get rid of extra }, ], etc
            data = json.loads(json_file)
            checklist = []
            #dependencies come in all these object forms
            for key in data:
                if key in DEPLIST:
                    for dep in data[key]:
                        version = "TBD"
                        resolved = None
                        if 'version' in data[key][dep]:
                            version = data[key][dep]['version']
                        if 'resolved' in data[key][dep]:
                            resolved = data[key][dep]['resolved']
                            domain = urlparse(resolved).netloc
                            if any(word in domain for word in dac_constants.INTERNAL_KEYWORDS):
                                continue
                        if not dep.startswith('@'):
                            result.append({'name': dep, 'version': version, 'resolved': resolved})    
    except Exception as e:
        #print(f"{filename} : NPM Error: {e}")
        raise
    return result

#checks the npm public repo for a package
def check_npm_public_repo(pkg, registryurl=None):
    try:
        if 'resolved' in pkg:
            return pkg['version']

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
        #print(f"NPM Error: {e}")
        return '0.0.0.0'

def check_npm_config(config):
    try:
        REGISTRY = re.compile(r"^registry\s*=\s*(.*)$", re.MULTILINE)
        matches = re.findall(REGISTRY, config['content'])
        if len(matches) == 0:
            return False
        for match in matches:
            if not any(x in match for x in dac_constants.INTERNAL_KEYWORDS):
                return False
        return True
    except Exception as e:
        print(f"NPM Error: {e}")
