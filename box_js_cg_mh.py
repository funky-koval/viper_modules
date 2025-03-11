# Made by Advanced Engineering

import os
import hashlib
import tempfile
import subprocess  # Replaces commands module
import shutil
import intel
import re
import json
from urllib.parse import urlparse
import requests
from viper.common.abstracts import Module
from viper.core.session import __sessions__
from viper.common.constants import VIPER_ROOT
from phish_collect.models import Phish

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
            with open(file, "r", encoding="utf-8", errors="ignore") as f:
                data = f.read()
        except (IOError, OSError) as e:
            self.log('error', 'Error reading file: {}'.format(e))
            return strings

        strings = re.findall(r"[\x1f-\x7e]{6,}", data)
        strings += [ws.decode("utf-16le") for ws in re.findall(r"(?:[\x1f-\x7e][\x00]){6,}", data)]
        return strings

    def duf(self, d, e, f):
        _Oxcele = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ+/"
        g = list(_Oxcele)  # Fixed typo here
        h = g[0:e]
        i = g[0:f]
        d = list(d)[::-1]
        j = 0
        for c, b in enumerate(d):
            if b in h:
                j += h.index(b) * (e ** c)

        k = ""
        while j > 0:
            k = i[j % f] + k
            j = j // f
        return int(k) or 0

    def hunter(self, h, u, n, t, e, r):
        result_str = ""
        i = 0
        while i < len(h):
            s = ""
            # Safeguard against index errors
            while i < len(h) and h[i] != n[e]:
                s += h[i]
                i += 1
            for j in range(len(n)):
                s = s.replace(n[j], str(j))
            if s:
                decoded = self.duf(s, e, 10) - t
                result_str += "".join(map(chr, [decoded]))
            i += 1
        return result_str

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
            domains_seen = set()
            boxjs_string = ''
            try:
                boxjs_run = subprocess.getoutput(cmd_line)
            except Exception as e:
                self.log("error", f"Error executing command: {e}")
                boxjs_run = ""
            lines = boxjs_run.split(',')
            for line in lines:
                boxjs_string += line

            try:
                self.log('warning', "URLs Found:")
                results_file = os.path.join(box_js_result_dir, f"{file_sha}-results", "urls.json")
                if os.path.exists(results_file):
                    with open(results_file, 'r') as fd:
                        for event in fd.readlines():
                            if "http" in event:
                                event_clean = re.sub(r"\s+", "", event).replace(",", "").replace("\"", "")
                                try:
                                    self.log('info', event_clean)
                                    self.log('warning', "URL Expander")
                                    site = intel.tiny_expand(event_clean)
                                    self.log('info', f'Expanded url: {site}')
                                    self.log('warning', "WebPulse review")
                                    parsed_uri = urlparse(site)
                                    domain = f"{parsed_uri.scheme}://{parsed_uri.netloc}/"
                                    domain_fqdn = parsed_uri.netloc

                                    if domain not in domains_seen:
                                        domains_seen.add(domain)
                                        try:
                                            url, category = intel.webpulse(domain)
                                            self.log("info", f"URL: {event_clean}\nCategory: {(url, category)}")
                                        except Exception as e:
                                            self.log('info', 'WebPulse Review Failed')
                                        try:
                                            self.log('warning', 'PhishTank Intel')
                                            phish, data = intel.check_PhishTank(Phish.clean_url(event_clean))
                                            if data:
                                                for entry in data:
                                                    self.log('info', 'Found in PhishTank DB')
                                                    report_json = json.dumps(entry)
                                                    d = json.loads(report_json)
                                                    rows = [[tag, detail] for tag, detail in d.items()]
                                                    self.log('table', dict(header=['Tag', 'Details'], rows=rows))
                                                self.log('info', f'PhishTank: {phish}')
                                            if not phish:
                                                self.log('info', 'Not Found in PhishTank DB')
                                        except Exception as e:
                                            self.log('info', 'PhishTank Review Failed')
                                        try:
                                            self.log('warning', 'ThreatCrowd Intel')
                                            threat_crowd_rows = []
                                            threat_crowd = intel.threat_crowd_domain(domain_fqdn)
                                            print(threat_crowd)
                                            for tag, detail in threat_crowd.items():
                                                threat_crowd_rows.append([tag, detail])
                                            self.log('table', dict(header=['Tag', 'Details'], rows=threat_crowd_rows))
                                        except Exception as e:
                                            pass
                                        try:
                                            self.log('warning', 'Google Intel')
                                            res = intel.google_check(event_clean)
                                            if res:
                                                self.log('warning', "URL found in Google Safe Browsing:")
                                                self.log('info', f"URL: {event_clean}\nThreat type: {res.get('threatType')}\n")
                                            else:
                                                self.log('warning', "URLs Not Found in Google Safe Browsing:")
                                        except Exception as e:
                                            self.log('info', 'Google Review Failed')
                                except Exception as e:
                                    pass
                else:
                    self.log('info', 'No URLs found')
            except Exception as e:
                pass

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
                    regex1 = r'(eval\(function\(h,u,n,t,e,r\))'
                    regex2 = r'return\s\w+\}\(\"(.*?)\)\)'
                    match1 = re.search(regex1, entry)
                    match2 = re.search(regex2, entry)
                    if match1 and match2:
                        code = match2.group(1)
                        code_list = code.split(',')
                        for idx, code_part in enumerate(code_list):
                            if code_part.isdigit():
                                code_list[idx] = int(code_part)
                            else:
                                code_list[idx] = code_part.replace("\"", "")
                        result = self.hunter(*code_list)
                        try:
                            self.log('warning', "Decoded Javascript")
                            self.log('info', result)
                        except Exception as e:
                            pass
            except Exception as e:
                self.log('error', f"Something went wrong: {e}")

    def api_run(self):
        super(BoxJs, self).run()
        if self.args is None:
            return
        if not __sessions__.is_set():
            return

        file_path = __sessions__.current.file.path
        file_name = __sessions__.current.file.name
        file_sha = __sessions__.current.file.sha256
        box_js_result_dir = tempfile.mkdtemp()

        cmd_line = f"/usr/local/bin/node {VIPER_ROOT}/modules/box-js-master/run.js --output-dir {box_js_result_dir} {file_path}"
        try:
            _ = subprocess.getoutput(cmd_line)
        except Exception as e:
            self.log("error", f"Error executing command: {e}")
        urls = []
        results_file = os.path.join(box_js_result_dir, f"{file_sha}.results", "urls.json")
        if os.path.exists(results_file):
            with open(results_file, 'r') as fd:
                urls = {re.sub(r'\s+', '', line).replace(",", "").replace('"','') for line in fd.readlines() if 'http' in line}
            urls = list(urls)

        shutil.rmtree(box_js_result_dir)
        return urls
