import os
import hashlib
import tempfile
import subprocess
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
        except (IOError, OSError):
            self.log('error', 'Could not read file')
            return strings

        strings = re.findall(r"[\x1f-\x7e]{6,}", data)
        strings += [ws.encode().decode("utf-16le") for ws in re.findall(r"(?:[\x1f-\x7e][\x00]){6,}", data)]
        return strings

    def duf(self, d, e, f):
        _Oxcele = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ+/"
        g = list(_Oxcele)
        h = g[:e]
        i = g[:f]
        d = list(d)[::-1]
        j = 0
        for c, b in enumerate(d):
            if b in h:
                j += h.index(b) * (e ** c)

        k = ""
        while j > 0:
            k = i[j % f] + k
            j = (j - (j % f)) // f
        return int(k) or 0

    def hunter(self, h, u, n, t, e, r):
        r = ""
        i = 0
        while i < len(h):
            j = 0
            s = ""
            while h[i] != n[e]:
                s = ''.join([s, h[i]])
                i += 1
            while j < len(n):
                s = s.replace(n[j], str(j))
                j += 1

            r += chr(self.duf(s, e, 10) - t)
            i += 1
        return r

    def run(self, *args):
        super(BoxJs, self).run(*args)
        if self.args is None:
            return
        if not __sessions__.is_set():
            self.log("error", "No session opened")
            return

        file_path = __sessions__.current.file.path
        file_sha = __sessions__.current.file.sha256

        if self.args.box:
            box_js_result_dir = tempfile.mkdtemp()
            cmd_line = f"/usr/local/bin/node {VIPER_ROOT}/modules/box-js-master/run.js --output-dir {box_js_result_dir} {file_path}"
            
            boxjs_run = subprocess.getoutput(cmd_line)
            self.log("warning", "Context:")
            self.log("info", boxjs_run)
            
            results_file = os.path.join(box_js_result_dir, f"{file_sha}-results", "urls.json")
            if os.path.exists(results_file):
                self.log('warning', "URLs Found:")
                with open(results_file, 'r', encoding='utf-8') as f:
                    for event in f.readlines():
                        event = re.sub(r"\s+", "", event).replace(",", "").replace("\"", "")
                        if "http" in event:
                            self.log('info', event)
            else:
                self.log('info', 'No URLs found')
            
            shutil.rmtree(box_js_result_dir)
        
        if self.args.other:
            try:
                file = __sessions__.current.file.path
                all_strings = self.extract_strings(file)
                for entry in all_strings:
                    hunter = re.search(r'(eval\(function\(h,u,n,t,e,r\))', entry)
                    if hunter:
                        code = re.search(r'return\s\w+\}\(\"(.*?)\)\)', entry).group(1)
                        code_list = code.split(',')
                        code_list = [int(c) if c.isdigit() else c.replace('"', '') for c in code_list]
                        result = self.hunter(*code_list)
                        self.log('warning', "Decoded Javascript")
                        self.log('info', result)
            except Exception as e:
                self.log('error', f"Something went wrong: {e}")

    def api_run(self):
        super(BoxJs, self).run()
        if self.args is None:
            return
        if not __sessions__.is_set():
            return

        file_path = __sessions__.current.file.path
        file_sha = __sessions__.current.file.sha256
        box_js_result_dir = tempfile.mkdtemp()

        cmd_line = f"/usr/local/bin/node {VIPER_ROOT}/modules/box-js-master/run.js --output-dir {box_js_result_dir} {file_path}"
        subprocess.getoutput(cmd_line)

        urls = []
        results_file = os.path.join(box_js_result_dir, f"{file_sha}.results", "urls.json")
        if os.path.exists(results_file):
            with open(results_file, 'r', encoding='utf-8') as fd:
                urls = list({re.sub(r'\s+', '', line).replace(",", "").replace('"', '') for line in fd.readlines() if 'http' in line})
        
        shutil.rmtree(box_js_result_dir)
        return urls
