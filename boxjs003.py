# -*- coding: utf-8 -*-
# This file is part of Viper - https://github.com/viper-framework/viper
# See the file 'LICENSE' for copying permission.

import os
import tempfile
import json
import re
import shutil
import subprocess
from urllib.parse import urlparse

from viper.common.abstracts import Module
from viper.core.session import __sessions__
from viper.core.config import __config__

cfg = __config__

class BoxJS(Module):
    cmd = 'boxjs'
    description = 'Analyze obfuscated JS files using BoxJS'
    authors = ['']

    def __init__(self):
        super(BoxJS, self).__init__()
        self.parser.add_argument('-b', '--box', action='store_true', help='Run via BoxJS')
        self.parser.add_argument('-o', '--other', action='store_true', help='Attempt Hunter decode')

    def extract_strings(self, file):
        """Extracts readable strings from the JavaScript file"""
        try:
            with open(file, "r", encoding="utf-8", errors="ignore") as f:
                data = f.read()
        except Exception as e:
            self.log('error', f"Error reading file: {e}")
            return []

        strings = re.findall(r"([\x1f-\x7e]{6,})", data)
        return strings

    def run_boxjs(self, file_path, file_sha):
        """Executes BoxJS on the JavaScript file"""
        self.log('debug', f"[DEBUG] Running BoxJS on: {file_path} ({file_sha})")

        box_js_result_dir = tempfile.mkdtemp()
        node_binary = shutil.which("node")

        if not node_binary:
            self.log('error', "Node.js is not installed or not found in PATH.")
            return None, None

        boxjs_script = os.path.join("/home/tak/.viper/modules/box-js", "run.js")
        self.log('debug', f"[DEBUG] BoxJS script path: {boxjs_script}")

        if not os.path.exists(boxjs_script):
            self.log('error', "BoxJS script not found. Ensure box-js is installed in modules directory.")
            return None, None

        cmd_line = [node_binary, boxjs_script, '--output-dir', box_js_result_dir, file_path]
        self.log('debug', f"[DEBUG] Executing command: {' '.join(cmd_line)}")

        try:
            subprocess.run(cmd_line, check=True)
            self.log('debug', "[DEBUG] BoxJS execution completed successfully.")
        except subprocess.CalledProcessError as e:
            self.log('error', f"BoxJS execution failed: {e}")
            return None, None

        return box_js_result_dir, file_sha

    def process_results(self, result_dir, file_sha):
        """Parses the output of BoxJS and extracts relevant URLs"""
        self.log('debug', f"[DEBUG] Checking for results file in: {result_dir}")

        results_file = os.path.join(result_dir, f"{file_sha}-results", "urls.json")

        if not os.path.exists(results_file):
            self.log('warning', f"No URLs found: {results_file} does not exist.")
            return []

        try:
            with open(results_file, "r", encoding="utf-8") as fd:
                urls = [re.sub(r'\s', '', line).replace(",", "").replace(":", "") for line in fd.readlines() if "http" in line]
        except Exception as e:
            self.log('error', f"Error reading results file: {e}")
            urls = []

        shutil.rmtree(result_dir)
        return urls

    def hunter_decode(self, file):
        """Attempts to decode Hunter-obfuscated JavaScript"""
        self.log('debug', "[DEBUG] Running Hunter decode...")
        all_strings = self.extract_strings(file)

        for entry in all_strings:
            regexp1 = r'(eval\(function\(h,u,n,t,e,r\))'
            regexp2 = r'return h\.apply\(u,\.split\(""\)\)'

            match1 = re.search(regexp1, entry)
            match2 = re.search(regexp2, entry)

            if match1 and match2:
                code_list = entry.split(',')
                for idx, code in enumerate(code_list):
                    if code.isdigit():
                        code_list[idx] = int(code)
                    else:
                        code_list[idx] = code.replace("\\", "")

                return self.hunter_logic(code_list)
        return None

    def hunter_logic(self, code_list):
        """Custom logic to decode Hunter obfuscation"""
        r = ""
        i = 0

        while i < len(code_list):
            j = 0
            while j < len(code_list[i]):
                r += "".join([chr(int(code_list[i][j]))])
                j += 1
            i += 1

        return r

    def run(self):
        """Main entry point for the module"""
        super(BoxJS, self).run()
        if self.args is None:
            return

        if not __sessions__.is_set():
            self.log('error', "No session opened. This command expects a file to be open.")
            return

        file_path = __sessions__.current.file.path
        file_name = __sessions__.current.file.name
        file_sha = __sessions__.current.file.sha256

        self.log('debug', f"[DEBUG] File path: {file_path}")
        self.log('debug', f"[DEBUG] File SHA256: {file_sha}")

        # Run BoxJS
        if self.args.box:
            result_dir, sha = self.run_boxjs(file_path, file_sha)
            if result_dir:
                self.log('debug', f"[DEBUG] Processing results from: {result_dir}")
                urls = self.process_results(result_dir, sha)
                if urls:
                    self.log('warning', "Extracted URLs:")
                    for url in urls:
                        self.log('info', url)
                else:
                    self.log('info', "No URLs extracted from JavaScript file.")

        # Run Hunter decoding
        elif self.args.other:
            try:
                result = self.hunter_decode(file_path)
                if result:
                    self.log('warning', "Decoded JavaScript:")
                    self.log('info', result)
            except Exception as e:
                self.log('error', f"Hunter decoding failed: {e}")

        else:
            self.log('error', "At least one of the parameters is required")
            self.usage()
