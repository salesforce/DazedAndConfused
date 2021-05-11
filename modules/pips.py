#
# Copyright (c) 2021, salesforce.com, inc.
# All rights reserved.
# SPDX-License-Identifier: BSD-3-Clause
# For full license text, see the LICENSE file in the repo root or https://opensource.org/licenses/BSD-3-Clause
#
###
#Checks pip files for potential and active dependency confusion attacks
###
#grabs actual dependencies from a requirements.txt file
import dac_constants
import toml
import re
import json
from pypi_simple import PyPISimple
from urllib.parse import urlparse

def get_pip_dependencies(filename, req_file):
    result = []
    try:

        #requirements file
        if filename.lower() == "requirements.txt":
            lines = [x.strip() for x in req_file.split('\n')]
            lines = [i for i in lines if i]
            for line in lines:
                if not line.startswith("#"):
                    line = re.sub(r"\[.*\]", "", line)
                    line = re.sub(r"\s*#.*?$", "", line)
                    line = line.split(',')[0]
                    tmp = re.split("==|>=|!=|~=|<|>", line)
                    if len(tmp) == 2:
                        result.append({'name': tmp[0].strip(), 'version': tmp[1].strip()})

        #pipfile
        if filename.lower() == "pipfile":
            pipfile = toml.loads(req_file)
            p = {}
            
            if 'packages' in pipfile:
                p = pipfile['packages']
            if 'dev-packages' in pipfile:
                p = {**p, **pipfile['dev-packages']}
            deps = []
            for dep in p:
                ver = p[dep]
                if not isinstance(p[dep], str):
                    ver = "TBA"
                ver = re.sub(r'(==|>=|<=|~=)', '', ver)
                result.append({'name': dep, 'version': ver})
                
        #pipfile.lock
        if filename.lower() == "pipfile.lock":
            pipcontents = json.loads(req_file)
            servers = []
            if 'sources' in pipcontents['_meta']:
                for source in pipcontents['_meta']['sources']:
                    servers.append(source['url'])
            external = True
            if servers:
                external = False
                for server in servers:
                    domain = urlparse(server).netloc
                    if not any(word in domain for word in dac_constants.INTERNAL_KEYWORDS):
                        external = True
            if not external:
                return result
            
            for block in pipcontents:
                if not block == "_meta":
                    for dep in pipcontents[block]:
                        name = dep
                        version = 'TBD'
                        if 'version' in pipcontents[block][dep]:
                            version = pipcontents[block][dep]['version']
                        result.append({'name': name, 'version': version})
    except Exception as e:
        print(f"PiP Error: {e}")
        raise
    return result

#checks the pip public repo for a package
def check_pip_public_repo(pkg, registryurl=None):
    try:
        base_url = 'https://pypi.org/simple/'
        if registryurl:
            base_url = registryurl

        with PyPISimple(endpoint=registryurl) as client:
            version = 0
            requests_page = client.get_project_page(pkg['name'])
            if requests_page:
                return requests_page.repository_version
            else:
                return '0.0.0.0'
    except Exception as e:
        #print(f"PiP Error: {e}")
        return '0.0.0.0'
