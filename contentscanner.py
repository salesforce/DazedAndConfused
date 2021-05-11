#
# Copyright (c) 2021, salesforce.com, inc.
# All rights reserved.
# SPDX-License-Identifier: BSD-3-Clause
# For full license text, see the LICENSE file in the repo root or https://opensource.org/licenses/BSD-3-Clause
#
import json
import os
import sys
import importlib
import concurrent.futures
from memoization import cached
import dac_constants

class Scanner:
    
    def __init__(self, modules_path, modules_file):
        #check modules.json and import our modules
        LIB_PATH = os.path.abspath(os.path.join(os.path.dirname(__file__), os.path.join(modules_path)))
        sys.path.append(LIB_PATH)

        #load modules.json
        with open(os.path.abspath(os.path.join(os.path.dirname(__file__), modules_file))) as f:
            self.MODULES = json.load(f)
        for module in self.MODULES['modules']:
            #set d as a ref to the module itself (for calling funcs)
            module['d'] = importlib.import_module(module['name'])
            #set funcs as refs to funcs from the strings
            module['parse_func'] = getattr(module['d'], module['parse_func'])
            module['repo_check_func'] = getattr(module['d'], module['repo_check_func'])
            module['manifest_file'] = [x.lower() for x in module['manifest_file']]
            module['lock_file'] = [x.lower() for x in module['lock_file']]
            if 'config_file' in module:
                module['config_file'] = module['config_file'].lower()
                module['config_parse_func'] = getattr(module['d'], module['config_parse_func'])

    # creates nested object output for a single manifest file
    @staticmethod
    def create_single_output(file, res):
        result = {'file': file, 'vulnerable': res['vulnerable'], 'sus': res['sus']}
        return result

    #checks a data string for dependency confusion
    def scan_contents(self, name, data, registryurl=None):
        errstr = ""
        try:
            singleresult = {}
            res = []
            #check file to see if we have a module for it
            for module in self.MODULES['modules']:
                if name.lower() in module['manifest_file'] or name.lower() in module['lock_file']:
                    errstr = f"{module['parse_func'].__name__}({name}, data)"
                    res = self.check_dependencies(module['parse_func'](name, data), module['repo_check_func'],
                                                  registryurl=registryurl)
                    break            

            #creates the output object for this result and append it to
            #the overall output if there was an actual vuln or sus
            singleresult = self.create_single_output(name, res)

            #return our results and an empty error list
            return {'result': singleresult}
        except Exception as e:
            #print(f"File validation error: {e} in scan_contents")
            return {'result': singleresult, 'errors': errstr}



    #check each dependency (now with threads!)
    def check_dependencies(self, deps, repo_check_method, registryurl=None):
        try:
            vulnerable = []
            sus = []
            res = []
            safe = []

            #remove dependencies in the ignore list
            tmpdeps = []
            for dep in deps:
                if dep['name'] not in dac_constants.IGNORE_LIST:
                    tmpdeps.append(dep)
            deps = tmpdeps
            
            #check each dependency with a new thread
            with concurrent.futures.ThreadPoolExecutor(max_workers=15) as executor:
                fut = [executor.submit(repo_check_wrapper, repo_check_method, dep, registryurl=registryurl) for dep in deps]
                for r in concurrent.futures.as_completed(fut):
                    res.append(r.result())
            res = sorted(res, key = lambda i: i['package']['name'])
            
            for result in res:
                if result['version'] == '0.0.0.0' or result['version'] == []:
                    #if it doesnt exist in public repo, its vulnerable
                    vulnerable.append(result['package']['name'])
                else:
                    if any(substring in result['package']['name'] for substring in dac_constants.PRIVATE_KEYWORDS):
                        #if its marked as private or seems like ours, but exists in public repo, then its a possible exploit in progress
                        sus.append(result['package']['name'])
                    else:
                        safe.append(result['package']['name'])
            
            #get rid of any empties
            safe = list(set(filter(None, safe)))
            if len(safe):
                safe.sort() 
            vulnerable = list(set(filter(None, vulnerable)))
            if len(vulnerable):
                vulnerable.sort()
            sus = list(set(filter(None, sus)))
            if len(sus):
                sus.sort()
            return {'vulnerable': vulnerable, 'sus': sus, 'safe': safe}
            
        except Exception as e:
            if "new thread" not in str(e):
                print(f"Error: {e} in check_dependencies")
            raise

# need this to cache results
@cached
def repo_check_wrapper(repo_check_method, pkg, registryurl=None):
    tmp = repo_check_method(pkg, registryurl=registryurl)
    return {'package': pkg, 'version': tmp}