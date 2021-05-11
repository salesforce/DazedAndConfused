#
# Copyright (c) 2021, salesforce.com, inc.
# All rights reserved.
# SPDX-License-Identifier: BSD-3-Clause
# For full license text, see the LICENSE file in the repo root or https://opensource.org/licenses/BSD-3-Clause
#
###
#Checks YARN files for potential and active dependency confusion attacks
###
import dac_constants
import urllib
import re
import json
import collections
from pyarn import lockfile
from urllib.parse import urlparse

#grabs actual dependencies from a yarn file
def get_yarn_dependencies(filename, contents):
    packages = []
    try:
        pat = re.compile(r'^\n(.*?):\n\s*version\s*"(.*?)"\n\s*resolved\s*"(.*?)"', re.MULTILINE)
        matches = re.finditer(pat, contents)
        for match in matches:
            resolved = match.group(3)
            domain = urlparse(resolved).netloc
            if any(word in domain for word in dac_constants.INTERNAL_KEYWORDS):
                continue            
            name = match.group(1).replace('"', '').split(', ')[0].rsplit('@', 1)[0].strip()
            if not name.startswith('@'):
                packages.append({'name': name, 'version': match.group(2), 'resolved': resolved})

    except Exception as e:
        #print(f"YARN Error: {e}")
        raise
    return packages

#checks the npm public repo for a package
def check_yarn_public_repo(pkg, registryurl=None):
    try:
        if 'resolved' in pkg:
            return pkg['version']

        base_url = 'https://registry.yarnpkg.com/'
        if registryurl:
            base_url = registryurl

        with urllib.request.urlopen(f"{base_url}{pkg['name']}", timeout=5) as url:
            data = json.loads(url.read().decode())
        if "dist-tags" in data:
            return data['dist-tags']['latest']
        else:
            return data['time']['unpublished']['versions'][0]
    except Exception as e:
        #print(f"YARN Error: {e}")
        return '0.0.0.0'
