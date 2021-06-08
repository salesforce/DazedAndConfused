#
# Copyright (c) 2021, salesforce.com, inc.
# All rights reserved.
# SPDX-License-Identifier: BSD-3-Clause
# For full license text, see the LICENSE file in the repo root or https://opensource.org/licenses/BSD-3-Clause
#
import json
import click
import os
import urllib
from contentscanner import Scanner

CONTEXT_SETTINGS = dict(help_option_names=['-h', '--help'])

@click.group(context_settings=CONTEXT_SETTINGS)
#default func when called
def dazed_and_confused():
    """ Dazed and Confused is a tool for scanning Github, Gitlab, and Swarm for instances of dependency confusion """
    pass

#checks a single file for dependency confusion
@dazed_and_confused.command('file', short_help='scans a single manifest file locally')
@click.option("-filename", "-f", required=True, help="file name")
@click.option("-resultsfile", "-rf", required=True, help="results file name")
@click.option("-registryurl", "-ru", required=False, help="registry url")
def check_file(filename, resultsfile, registryurl):
    """ The [file] command scans a single manifest file locally """
    try:
        with open(filename,"r") as f:
            data = f.read()
        FILESCANNER = Scanner("./modules", "modules.json")
        singleresult = FILESCANNER.scan_contents(os.path.basename(filename), data, registryurl=registryurl)
        write_output_file(resultsfile, singleresult)
    except Exception as e:
        print(f"Error: {e} in check_file")

#checks a single url for dependency confusion
@dazed_and_confused.command('url', short_help='scans a single manifest file via url')
@click.option("-manifestname", "-mn", required=True, help="manifest file name (e.g. package.json)")
@click.option("-url", "-u", required=True, help="file url")
@click.option("-resultsfile", "-rf", required=True, help="results file name")
@click.option("-registryurl", "-ru", required=False, help="registry url")
def check_url(manifestname, url, resultsfile, registryurl):
    """ The [url] command scans a single manifest file via url """
    try:
        FILESCANNER = Scanner("./modules", "modules.json")
        data = urllib.request.urlopen(url).read().decode('ascii')
        singleresult = FILESCANNER.scan_contents(os.path.basename(manifestname), data, registryurl=registryurl)
        write_output_file(resultsfile, singleresult)
    except Exception as e:
        print(f"Error: {e} in check_url")

#writes json output to filename
def write_output_file(resultsfile, resultsjson, print_name=True):
    try:
        jsonoutput = json.dumps(resultsjson, indent=4)
        with open(resultsfile, "w") as file:
            file.write(jsonoutput)
        if print_name:
            print(os.path.realpath(resultsfile))
    except Exception as e:
        print(f"Error: {e} in write_output_file")  

if __name__ == '__main__':
    dazed_and_confused()        
