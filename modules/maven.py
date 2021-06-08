#
# Copyright (c) 2021, salesforce.com, inc.
# All rights reserved.
# SPDX-License-Identifier: BSD-3-Clause
# For full license text, see the LICENSE file in the repo root or https://opensource.org/licenses/BSD-3-Clause
#
###
#Checks maven files for potential and active dependency confusion attacks
###
import dac_constants
import urllib
from lxml import etree as ElementTree
from ratelimit import limits, sleep_and_retry
from urllib.parse import urlparse
import json
import re

#grabs actual dependencies from an pom file
def get_maven_dependencies(filename, xml_file):
    result = []
    try:
        #the lxml parser hates encoding definitions for whatever reason, remove em
        xml_file = xml_file.replace("\n", "")
        xml_file = re.sub(r'encoding=["\'](UTF|utf)\-?8["\']', "", xml_file)
        xml_file = re.sub("xmlns.*?\s", "", xml_file)
        parser = ElementTree.XMLParser(recover=True)
        xmldoc = ElementTree.fromstring(xml_file, parser)
        
        #get properties
        propxml = xmldoc.findall('.//properties')[0]
        properties = {}
        if propxml is not None and len(propxml) > 0:
            for property in propxml:
                properties[property.tag] = property.text
        
        # grab repositories
        external = True
        repositories = xmldoc.findall('.//repository')
        if repositories is not None and len(repositories) > 0:
            external = False
            for repository in repositories:
                url = repository.find('.//url')
                if url is not None:
                    domain = urlparse(url.text).netloc
                    external = external or not any(word in domain for word in dac_constants.INTERNAL_KEYWORDS)

        #if any repo is external     
        if external:
            #grab dependencies/plugins
            deps = xmldoc.findall('.//dependency') + xmldoc.findall('.//plugin')
            for dep in deps:
                pkg = dep.find('.//artifactId')
                #the name exists... so thats something
                if pkg is not None:
                    pkg = fix_prop(pkg.text, properties)
                gid = dep.find('.//groupId')
                if gid is not None:
                    gid = fix_prop(gid.text, properties)
                version = dep.find('.//version')
                if version is not None:
                    version = fix_prop(version.text, properties)
                if ',' in version or 'SNAPSHOT' in version:
                    version = None
                #if there is a name, a groupid, and a non-snapshot, non-range version, then it isnt vulnerable
                #otherwise, we add it to be checked
                if gid is None or version is None:
                    result.append({'name': pkg, 'group': gid, 'version': version})

    except Exception as e:
        #print(f"Maven Error: {e}")
        raise
    return result

def fix_prop(name, properties):
    match = re.search(r'\$\{(.*?)\}', name)
    if match and match.group(1) in properties:
        name = name.replace(match.group(), properties[match.group(1)])
    return name
        
@sleep_and_retry
@limits(calls=10, period=1)
#checks the maven public repo for a package
def check_maven_public_repo(pkg, registryurl=None):
    try:
        if 'group' in pkg and pkg['group'] is not None:
            qs = f"a:%22{pkg['name']}%22%20AND%20g%3A%22{pkg['group']}%22"
        else:
            qs = f"a:%22{pkg['name']}%22"

        mavenurl = f"https://search.maven.org/solrsearch/select?q={qs}"
        if registryurl:
            mavenurl = f"{registryurl}solrsearch/select?q={qs}"

        with urllib.request.urlopen(mavenurl, timeout=10) as url:
            data = json.loads(url.read().decode())     
            if data['response']['numFound'] == 0:
                return '0.0.0.0'
            else:
                return data['response']['docs'][0]['latestVersion']
    except Exception as e:
        #print(f"Maven Error: {e}")
        return '0.0.0.0'
