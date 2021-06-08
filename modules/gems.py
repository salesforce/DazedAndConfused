#
# Copyright (c) 2021, salesforce.com, inc.
# All rights reserved.
# SPDX-License-Identifier: BSD-3-Clause
# For full license text, see the LICENSE file in the repo root or https://opensource.org/licenses/BSD-3-Clause
#
###
#Checks GEMS files for potential and active dependency confusion attacks
###
import dac_constants
import urllib
import re
import json
import collections
from gemfileparser import GemfileParser

#the gemfile parser didnt have the option to parse from a string, so we added it here
class GemfileParserFromString(GemfileParser):
    def __init__(self, filecontents, filename):
        GemfileParser.filepath = filename
        GemfileParser.current_group = 'runtime'
        GemfileParser.appname = ""
        GemfileParser.dependencies = {
            'development': [],
            'runtime': [],
            'dependency': [],
            'test': [],
            'production': [],
            'metrics': [],
        }
        GemfileParser.contents = filecontents.split("\n")
        GemfileParser.gemspec = filename.endswith(('.gemspec', '.podspec'))        

#trying out just classing a whole parser
class LockParser():
    def __init__(self, file):
        self.file = file

    def parse(self):
        deps = []
        parts = self.get_parts(self.file)
        for part in parts:
            remoteserver = self.get_server(part['contents'])
            items = self.get_deps(part['contents'])
            for item in items:
                deps.append(item)
        return deps
    
    def get_parts(self, lockfile):
        DEPENDENCIES = "DEPENDENCIES"
        GIT = "GIT"
        GEM = "GEM"
        PATH = "PATH"
        PLUGIN = "PLUGIN SOURCE"
        HAS_DEPS= [GIT, GEM, PATH, PLUGIN, DEPENDENCIES]
        ret = []
        parts = lockfile.split('\n\n')
        for part in parts:
            if list(filter(part.startswith, HAS_DEPS)) != []:
                name = part.partition('\n')[0]
                contents = "\n".join(part.split("\n")[1:])
                ret.append({'name': name, 'contents': contents})
        return ret

    def get_server(self, block):
        REMOTE = re.compile("^  remote: (.*)$", re.MULTILINE)
        remoteserver = re.search(REMOTE, block)
        if remoteserver is not None:
            remoteserver = remoteserver.group(1)
            if any(x in remoteserver for x in dac_constants.INTERNAL_KEYWORDS):
                return {'server': remoteserver, 'internal': True}
            else:
                return {'server': remoteserver, 'internal': False}
        else:
            return None
        
    def get_deps(self, block):
        ret = []
        if "specs:" in block:
            SPECS = re.compile("^  specs:\n", re.MULTILINE)
            items = re.split(SPECS, block)
            if len(items) == 2:
                items = items[1].split("\n")
                items = [x.strip() for x in items]
        else:
            items = block.split("\n")
            items = [x.strip() for x in items]        
        for item in items:
            ret.append(self.get_dep(item))
        return ret

    def get_dep(self, line):
        ret = {'name': "", 'version': "TBD"}
        line = line.split(' (')
        ret['name'] = line[0]
        if ret['name'].endswith('!'):
            ret['name'] = ret['name'][:-1]
        if len(line) == 2:
            ret['version'] = re.sub(r'(~->|~>|>=|<=|=|\)) ', '', line[1]).split(', ')[0]
        return ret    

#grabs actual dependencies from a gemfile file
def get_gems_dependencies(filename, contents):
    result = []
    try:
        #its a gemfile
        if filename.lower() == "gemfile":
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
            parser = GemfileParserFromString(contents, filename)
            try:
                deps = parser.parse()
            except:
                deps = {}
            for key in deps:
               if deps[key]:
                   for dependency in deps[key]:
                       ver = "TBD"
                       if dependency.requirement:
                           ver = dependency.requirement[0]
                           #get rid of the versioning qualifiers
                           ver = re.sub(r'(~->|~>|>=|<=|=) ', '', ver)
                       result.append({'name': dependency.name, 'version': ver})
        #its a lockfile               
        elif filename.lower() == "gemfile.lock":
            result = LockParser(contents).parse()
    except Exception as e:
        #print(f"GEMS Error: {e}")
        raise
    return result

#checks the gems public repo for a package
def check_gems_public_repo(pkg, registryurl=None):
    try:
        base_url = 'https://rubygems.org/'
        if registryurl:
            base_url = registryurl

        with urllib.request.urlopen(f"{base_url}api/v1/gems/{pkg['name']}.json", timeout=10) as url:
            data = json.loads(url.read().decode())
        return data['version']
    except Exception as e:
        #print(f"GEMS Error: {e}")
        return '0.0.0.0'
