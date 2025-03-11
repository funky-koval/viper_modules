import os
import hashlib
import tempfile
import shutil
import re
import json
import subprocess
from urllib.parse import urlparse
import requests
from viper.common.abstracts import Module
from viper.core.session import __sessions__
from viper.common.constants import VIPER_ROOT
from phish_collect.models import Phish

# Import intel module - assuming this is a local module
import intel

class BoxJs(Module):
    cmd = 'boxjs'
    description = 'Analyse obfuscated JS files'
    authors = ['viper']

    def __init__(self):
        super(BoxJs, self).__init__()
        self.parser.add_argument('-b', '--box', action='store_true', help='Run via BoxJs')
        self.parser.add_argument('-o', '--other', action='store_true', help='Attempt Hunter decode')

    def extract_strings(self, file):
        strings = []
        try:
            with open(file, "r", errors="ignore") as f:
                data = f.read()
        except (IOError, OSError) as e:
            self.log('error', f'Error reading file: {e}')
            return strings
            
        strings = re.findall(r"[\x1f-\x7e]{6,}", data)
        strings += [str(ws.decode("utf-16le")) for ws in re.findall(r"(?:[\x1f-\x7e][\x00]){6,}", data.encode())]
        return strings

    def duf(self, d, e, f):
        _Oxcele = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ+/"
        g = list(_Oxcele)  # Fixed variable name from _0xcele to _Oxcele
        h = g[0:e]
        i = g[0:f]
        d = list(d)[::-1]
        j = 0
        for c, b in enumerate(d):
            if b in h:
                j = j + h.index(b)*e**c

        k = ""
        while j > 0:
            k = i[j%f] + k
            j = (j - (j % f)) // f
        return int(k) or 0

    def hunter(self, h, u, n, t, e, r):
        r = ""
        i = 0
        while i < len(h):
            j = 0
            s = ""
            while h[i] is not n[e]:
                s = ''.join([s, h[i]])
                i = i + 1
            while j < len(n):
                s = s.replace(n[j], str(j))
                j += 1

            r = "".join([r, "".join(map(chr, [self.duf(s, e, 10) - t]))])
            i = i + 1
        return r

    def run(self, *args):
        super(BoxJs, self).run(*args)
        if self.args is None:
            return
        if not __sessions__.is_set():
            self.log("error", "No session opened")
            return

        # Set variables
        file_path = __sessions__.current.file.path
        file_name = __sessions__.current.file.name
        file_sha = __sessions__.current.file.sha256

        if self.args.box:
            box_js_result_dir = tempfile.mkdtemp()
            cmd_line = f"/usr/local/bin/node {VIPER_ROOT}/modules/box-js-master/run.js --output-dir {box_js_result_dir} {file_path}"
            
            # Get the output using subprocess instead of commands
            try:
                boxjs_run = subprocess.check_output(cmd_line, shell=True, text=True)
            except subprocess.SubprocessError as e:
                self.log('error', f'Error running box-js: {e}')
                boxjs_run = ""
                
            domains_seen = set()
            boxjs_string = ''
            lines = boxjs_run.split(',')
            for line in lines:
                boxjs_string += line

            try:
                # Get URLs from file
                self.log('warning', "URLs Found:")
                results_file = os.path.join(box_js_result_dir, f"{file_sha}-results", "urls.json")
                if os.path.exists(results_file):
                    with open(results_file, 'r') as f:
                        for event in f.readlines():
                            if "http" in event:
                                event = re.sub(r"\s+", "", event).replace(",", "").replace("\"", "")
                                try:
                                    self.log('info', event)
                                    self.log('warning', "URL Expander")
                                    site = intel.tiny_expand(event)
                                    self.log('info', f'Expanded url: {site}')
                                    self.log('warning', "WebPulse review")
                                    parsed_uri = urlparse(site)
                                    domain = f"{parsed_uri.scheme}://{parsed_uri.netloc}/"
                                    domain_fqdn = parsed_uri.netloc

                                    if domain not in domains_seen:
                                        domains_seen.add(domain)
                                        try:
                                            url, category = intel.webpulse(domain)
                                            self.log("info", f"URL: {event}\nCategory: {url}, {category}")
                                        except Exception as e:
                                            self.log('info', f'WebPulse Review Failed: {e}')
                                        
                                        try:
                                            self.log('warning', 'PhishTank Intel')
                                            phish, data = intel.check_PhishTank(Phish.clean_url(event))
                                            if data:
                                                for entry in data:
                                                    self.log('info', 'Found in PhishTank DB')
                                                    report_json = json.dumps(entry)
                                                    d = json.loads(report_json)
                                                    rows = [[tag, detail] for tag, detail in d.items()]
                                                    self.log('table', dict(header=['Tag', 'Details'], rows=rows))
                                                self.log('info', f'PhishTank: {phish}')
                                            if phish == False:
                                                self.log('info', 'Not Found in PhishTank DB')
                                        except Exception as e:
                                            self.log('info', f'PhishTank Review Failed: {e}')
                                        
                                        try:
                                            self.log('warning', 'ThreatCrowd Intel')
                                            threat_crowd_rows = []
                                            threat_crowd = intel.threat_crowd_domain(domain_fqdn)
                                            print(threat_crowd)  # Fixed: added parentheses
                                            for tag, detail in threat_crowd.items():  # Changed iteritems() to items()
                                                threat_crowd_rows.append([tag, detail])
                                            self.log('table', dict(header=['Tag', 'Details'], rows=threat_crowd_rows))
                                        except Exception as e:
                                            self.log('info', f'ThreatCrowd Review Failed: {e}')
                                        
                                        try:
                                            self.log('warning', 'Google Intel')
                                            res = intel.google_check(event)
                                            if res:
                                                self.log('warning', "URL found in Google Safe Browsing:")
                                                self.log('info', f"URL: {event}\nThreat type: {res['threatType']}\n")
                                            else:
                                                self.log('warning', "URLs Not Found in Google Safe Browsing:")
                                        except Exception as e:
                                            self.log('info', f'Google Review Failed: {e}')
                                    else:
                                        self.log('info', 'WebPulse Reviewed Above')
                                except Exception as e:
                                    self.log('info', f'Error processing URL {event}: {e}')
                else:
                    self.log('info', 'No URLs found')
            except Exception as e:
                self.log('error', f'Error processing results: {e}')

            # Clean up temp dir
            shutil.rmtree(box_js_result_dir)

            # Print output to screen
            self.log("warning", "Context:")
            self.log("info", boxjs_string)

        if self.args.other:
            try:
                file = __sessions__.current.file.path
                all_strings = self.extract_strings(file)
                for entry in all_strings:
                    try:
                        regex1 = '(eval\(function\(h,u,n,t,e,r\))'
                        regex2 = 'return\s\w+\}\(\"(.*?)\)\)'
                        hunter_match = re.search(regex1, entry)
                        
                        if hunter_match:
                            hunter = hunter_match.group(1)
                            code_match = re.search(regex2, entry)
                            
                            if code_match:
                                code = code_match.group(1)
                                code_list = code.split(',')
                                
                                for idx, code_item in enumerate(code_list):
                                    if code_item.isdigit():
                                        code_list[idx] = int(code_item)
                                    else:
                                        code_list[idx] = code_item.replace("\"", "")
                                
                                result = self.hunter(*code_list)
                                self.log('warning', "Decoded Javascript")
                                self.log('info', result)
                    except Exception as e:
                        continue  # Continue with next string if this one fails
            except Exception as e:
                self.log('error', f"Something went wrong: {e}")

    def api_run(self):
        super(BoxJs, self).run()
        if self.args is None:
            return
        if not __sessions__.is_set():
            return

        # Set variables
        file_path = __sessions__.current.file.path
        file_name = __sessions__.current.file.name
        file_sha = __sessions__.current.file.sha256
        box_js_result_dir = tempfile.mkdtemp()

        # Set command to execute
        cmd_line = f"/usr/local/bin/node {VIPER_ROOT}/modules/box-js-master/run.js --output-dir {box_js_result_dir} {file_path}"
        
        # Get the output using subprocess instead of commands
        try:
            _ = subprocess.check_output(cmd_line, shell=True, text=True)
        except subprocess.SubprocessError:
            # Handle error silently as the original code did
            pass

        urls = []
        results_file = os.path.join(box_js_result_dir, f"{file_sha}.results", "urls.json")
        if os.path.exists(results_file):
            with open(results_file) as fd:
                urls = {re.sub('\s+','', line).replace(",","").replace('"','') for line in fd.readlines() if 'http' in line}
            urls = list(urls)

        # Clean up tmp dir
        shutil.rmtree(box_js_result_dir)
        return urls
