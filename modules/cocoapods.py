#
# Copyright (c) 2021, salesforce.com, inc.
# All rights reserved.
# SPDX-License-Identifier: BSD-3-Clause
# For full license text, see the LICENSE file in the repo root or https://opensource.org/licenses/BSD-3-Clause
#
###
#Checks cocoapods files for potential and active dependency confusion attacks
###
import requests
import json
import re
import yaml
import dac_constants

#grabs actual dependencies from a Podfile
def get_cocoapods_dependencies(filename, contents):
    result = []
    try:
        if filename.lower() == "podfile":
            #check the sources, if they are all internal, this whole file is safe
            sources = []
            pat = re.compile(r'^source\s*[\'"](.*?)[\'"]', re.MULTILINE)
            matches = re.finditer(pat, contents)
            for match in matches:
                sources.append(match.group(1))
            external = False
            for source in sources:
                if not any(x in source for x in dac_constants.INTERNAL_KEYWORDS):
                    external = True
                    break
            if not external:
                return result

            #parse out the pods
            pat = re.compile(r"^\s*?pod (.*)$", re.MULTILINE)
            results = re.findall(pat, contents)
            for item in results:
                tmp = item.replace("'", "").split(',')
                tmp = [re.sub(r'[~><]', '', x).strip() for x in tmp]
                if len(tmp) > 1:
                    result.append({'name': tmp[0], 'version': tmp[1]})
                    
        elif filename.lower() == "podfile.lock":
            #pod lock files are YAML, so this is easier
            data = yaml.load(contents, Loader=yaml.Loader)
            if 'DEPENDENCIES' in data:
                for dep in data['DEPENDENCIES']:
                    tmp = dep.split(" ", 1)
                    name = tmp[0]
                    version = "TBD"
                    if len(tmp) > 1:
                        if tmp[1].startswith('(from'):
                            version = re.search(r'\(from `(.*?)`', tmp[1]).group(1)
                            tmp[1] = tmp[1].replace(")", "")
                        else:
                            version = re.sub(r'[\(\)~>< ]', '', tmp[1]).strip()
                    result.append({'name': name, 'version': version})

        #disregard any dependencies that point to internal git repos
        results = []
        for dep in result:
            if not any(substring in dep['version'] for substring in dac_constants.INTERNAL_KEYWORDS):
                results.append(dep)
                
    except Exception as e:
        #print(f"cocoapods Error: {e}")
        raise
    return results

#checks the cocoapods public repo for a package
def check_cocoapods_public_repo(pkg, registryurl=None):
    try:
        data = '{"params":"query=' + pkg['name'] + '"}'
        ret = requests.post("https://wbhhamhynm-dsn.algolia.net/1/indexes/cocoapods/query?x-algolia-application-id=WBHHAMHYNM&x-algolia-api-key=4f7544ca8701f9bf2a4e55daff1b09e9", data, timeout=5)
        data = ret.json()
        if data['hits']:
            if data['hits'][0]['name'] == pkg['name']:
                return data['hits'][0]['version']
        return '0.0.0.0'  
    except Exception as e:
        #print(f"cocoapods Error: {e}")
        return '0.0.0.0'
