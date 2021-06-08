#
# Copyright (c) 2021, salesforce.com, inc.
# All rights reserved.
# SPDX-License-Identifier: BSD-3-Clause
# For full license text, see the LICENSE file in the repo root or https://opensource.org/licenses/BSD-3-Clause
#
###
#Checks composer files for potential and active dependency confusion attacks
###
import dac_constants
import urllib
import json
import re
from urllib.parse import urlparse

#grabs actual dependencies from a composer file
def get_composer_dependencies(filename, contents):
    results = []
    try:
        composerdata = json.loads(contents)
        if filename.lower() == "composer.json":
            if 'require' in composerdata:
                for dep in composerdata['require']:
                    if not dep == "php":
                        results.append({'name': dep, 'version': composerdata['require'][dep]})
        elif filename.lower() == "composer.lock":
            if 'packages' in composerdata:    
                for dep in composerdata['packages']:
                    name = dep['name']
                    version = dep['version']
                    url = dep['source']['url']
                    domain = urlparse(url).netloc
                    if any(word in domain for word in dac_constants.INTERNAL_KEYWORDS):
                        continue                    
                    results.append({'name': name, 'version': version, 'url': url})
    except Exception as e:
        #print(f"composer Error: {e}")
        raise
    return results

#checks the composer public repo for a package
def check_composer_public_repo(pkg, registryurl=None):
    try:
        if 'url' in pkg:
            return pkg['version']

        base_url = 'https://repo.packagist.org/p2/'
        if registryurl:
            base_url = registryurl

        with urllib.request.urlopen(f"{base_url}{pkg['name']}.json", timeout=10) as url:
            data = json.loads(url.read().decode())
        if 'packages' in data:
            if pkg['name'] in data['packages']:
                if len(data['packages'][pkg['name']]) > 0:
                    return data['packages'][pkg['name']][0]['version']
        return '0.0.0.0'    
    except Exception as e:
        #print(f"composer Error: {e}")
        return '0.0.0.0'
