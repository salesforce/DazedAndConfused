#
# Copyright (c) 2021, salesforce.com, inc.
# All rights reserved.
# SPDX-License-Identifier: BSD-3-Clause
# For full license text, see the LICENSE file in the repo root or https://opensource.org/licenses/BSD-3-Clause
#
###
#Checks gradle files for potential and active dependency confusion attacks
###
import dac_constants
import urllib
import json
import re
from ratelimit import limits, sleep_and_retry
from urllib.parse import urlparse

class GradleSlurper:
    def __init__(self, source):
        self.source = source
        fixed = re.sub(re.compile(r"\n^\s*$\n", re.DOTALL|re.MULTILINE), "\n", self.source)
        self.lines = fixed.split("\n")
        self.indent = 0
        self.defs = self.get_defs()
        self.data = self.parse()
        self.repositories = self.get_repos()
        self.dependencies = self.get_dependencies()

    def get_block(self):
        line = self.lines.pop(0)
        result = re.search(r"^(?:\s*)(.*?)(?:\s*\{\s*)$", line)
        results = {result.group(1): []}
        blockindent = self.get_indent(self.lines[0])
        blocklines = []
        while self.lines and self.get_indent(self.lines[0]) == blockindent:
            line = self.lines[0]
            if self.is_block(line):
                blocklines.append(self.get_block())
            else:
                tmp = self.lines.pop(0).strip()
                if not tmp == "}" and not tmp.startswith("//"):
                    blocklines.append(tmp)
        results[result.group(1)] = blocklines
        return results

    def get_indent(self, line):
        indent = re.search(r"^(\s*)", line)
        if not indent:
            return 0
        return len(indent.group(0))

    def is_block(self, line):
        if not re.search(r"(\s*\{\s*)$", line):
            return False
        else:
            return True
        
    def parse(self):
        results = {}
        while True:
            if len(self.lines) == 0:
                break
            line = self.lines[0]
            self.indent = self.get_indent(line)
            if self.is_block(line):
                results = {**results, **self.get_block()}
            else:
                tmp = self.lines.pop(0).strip()
                if not tmp == "}":
                    #results.append(tmp)
                    pass
        return results
    
    def get_repo(self, repo):
        repo = self.replace_def(repo)
        result = re.search(r"['\"]((?:http|/).*?)['\"]", repo)
        if result:
            return result.group(1)
        else:
            return None
        
    def get_repos(self):
        results = []
        if 'repositories' in self.data:
            for repo in self.data['repositories']:
                if isinstance(repo, str):
                    result = self.get_repo(repo)
                    if result:
                        results.append(result)
                else:
                    block = next(iter(repo))
                    for item in repo[block]:
                        if isinstance(item, str):
                            result = self.get_repo(item)
                            if result:
                                results.append(result)
        results = list(set(results))
        return results

    def get_dependencies(self):
        results = self.get_deps(self.data)
        for block in self.data:
            for item in self.data[block]:
                if isinstance(item, dict):
                    results = results + self.get_deps(item)   
        return results

    def get_deps(self, data):
        results = []
        if 'dependencies' in data:
            for dep in data['dependencies']:
                if isinstance(dep, dict):
                    dep = next(iter(dep))
                dep = re.sub(r"(classpath |testCompile |compile |implementation |testImplementation |extraLibs |runtime )", "", dep).strip()
                if 'name:' not in dep:
                #it was set up like 'group:package:version'
                    if dep.startswith("'") or dep.startswith('"'):
                        i = re.sub("[\,'\"]", "", dep).strip().split(':')
                        if len(i) == 3:
                            #if there is a name, a groupid, and a non-snapshot, non-range version, then it isnt vulnerable
                            #otherwise, we add it to be checked
                            i[2] = self.replace_def(i[2])
                            if ',' in i[2] or 'SNAPSHOT' in i[2]:
                                results.append({'name': i[1], 'version': i[2], 'group': i[0]})
                        elif len(i) == 2:
                            results.append({'name': i[1], 'version': 'TBD', 'group': i[0]})
                else:
                    if dep.startswith("group"):
                        dep = re.sub(r"//.*", "", dep)
                        r = re.search('name:\s*[\'"](.*?)[\'"]()', dep)
                        name = r.group(1) if r else None
                        r = re.search('group:\s*[\'"](.*?)[\'"]()', dep)
                        group = r.group(1) if r else None
                        r = re.search('version:\s*[\'"](.*?)[\'"]()', dep)
                        version = r.group(1) if r else None
                        if name:
                            if group:
                                if version:
                                    if ',' in version or 'SNAPSHOT' in version:
                                        results.append({'name': name, 'version': version, 'group': group})
                                else:
                                    results.append({'name': name, 'version': '0.0.0.0', 'group': group})
                            else:
                                if version:
                                    results.append({'name': name, 'version': version})
                                else:
                                    results.append({'name': name, 'version': '0.0.0.0'})   
        return results

    def get_defs(self):
        deflist = []
        results = []
        for line in self.lines:
            if line.startswith("def "):
                deflist.append(line[4:])
        for adef in deflist:
            adef = adef.split(' = ')
            if len(adef) == 2:
                if not adef[1].startswith("[") and not adef[1].startswith("{"):
                    if " ?: " in adef[1]:
                        adef[1] = adef[1].split(" ?: ")[1]            
                    adef[1] = adef[1][1:-1]
                    results.append({'name': adef[0], 'value': adef[1]})
        return results

    def replace_def(self, text):
        result = ""
        if text.startswith('$'):
            for adef in self.defs:
                text = text.replace(f"${adef['name']}", adef['value'])
        else:
            for adef in self.defs:
                pat = f"{adef['name']}.concat\(['\"]"
                pat = re.compile(pat)
                text = re.sub(pat, '"' + adef['value'], text)
        return text

#grabs actual dependencies from a gradle.build file
def get_gradle_dependencies(filename, contents):
    results = []
    try:
        if filename.lower() == "gradle.lockfile":
            lines = contents.splilt("\n")
            lines[:] = [x for x in lines if not x.startswith('#')]
            for line in lines:
                line = line.split("=")[0]
                items = line.split(":")
                if len(items) == 3:
                    name = items[1]
                    version = items[2]
                    group = items[0]
                    results.append({'name': name, 'version': version, 'group': group})
        else:
            gradleresults = GradleSlurper(contents)
            
            if len(gradleresults.repositories) > 0:
                internal = True
                for match in gradleresults.repositories:
                    domain = urlparse(match).netloc
                    if not any(word in domain for word in dac_constants.INTERNAL_KEYWORDS):
                        internal = False
                        break
                if internal:
                    return results

            results = gradleresults.dependencies
        
    except Exception as e:
        #print(f"Gradle Error: {e}")
        raise
    return results

@sleep_and_retry
@limits(calls=10, period=1)
#checks the maven public repo for a package
def check_gradle_public_repo(pkg, registryurl=None):
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
