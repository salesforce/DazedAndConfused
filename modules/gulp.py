#
# Copyright (c) 2021, salesforce.com, inc.
# All rights reserved.
# SPDX-License-Identifier: BSD-3-Clause
# For full license text, see the LICENSE file in the repo root or https://opensource.org/licenses/BSD-3-Clause
#
###
#Checks GULP files for potential and active dependency confusion attacks
###
import urllib
import json
import re

#grabs actual dependencies from a gulpfile.js file
def get_gulp_dependencies(filename, contents):
    results = []
    try:
        #gulp is pretty straightforward js
        pat = re.compile(r"require\(\s*['\"](.*?)['\"]\s*\)", re.DOTALL)
        result = re.findall(pat, contents)
        for item in result:
            if not item.startswith('./') and not item.startswith('@'):
                results.append({'name': item, 'version': "TBD"})

    except Exception as e:
        #print(f"gulp Error: {e}")
        raise
    return results

#checks the npm public repo for a package
def check_gulp_public_repo(pkg, registryurl=None):
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
        #print(f"gulp Error: {e}")
        return '0.0.0.0'
