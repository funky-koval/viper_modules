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
    description = 'Analyse obfuscated JS files using BoxJS'
    authors = ['']

    def __init__(self):
        super(BoxJS, self).__init__()
        self.parser.add_argument('-b', '--box', action='store_true', help='Run via BoxJS')
        self.parser.add_argument('-o', '--other', action='store_true', help='Attempt Hunter decode')

    def extract_strings(self, file):
        """ Extracts readable strings from the JavaScript file """
        self.log('debug', f"[DEBUG] Extracting strings from: {file}")
        try:
            with open(file, "r", encoding="utf-8", errors="ignore") as f:
                data = f.read()
        except Exception as e:
            self.log('error', f"[ERROR] Failed to read file: {e}")
            return []

        strings = re.findall(r"([\x1f-\x7e]{6,})", data)
        self.log('debug', f"[DEBUG] Found {len(strings)} strings.")
        return strings

    def run_boxjs(self, file_path, file_sha):
        """ Executes BoxJS on the JavaScript file """

        # Ensure the file path is valid
        if not file_path or not isinstance(file_path, (str, bytes, os.PathLike)):
            self.log('error', f"[ERROR] Invalid file_path: {file_path}")
            return None

        self.log('debug', f"[DEBUG] Running BoxJS on: {file_path} ({file_sha})")

        # Create a temporary directory for BoxJS output
        box_js_result_dir = tempfile.mkdtemp()
        self.log('debug', f"[DEBUG] Created temporary results directory: {box_js_result_dir}")

        # Locate Node.js binary
        node_binary = shutil.which("node")
        if not node_binary:
            self.log('error', "[ERROR] Node.js is not installed or not found in PATH.")
            return None

        # Define BoxJS script path
        boxjs_script = os.path.join(cfg.modules.path, "box-js-master", "run.js")
        if not os.path.exists(boxjs_script):
            self.log('error', "[ERROR] BoxJS script not found. Ensure box-js-master is installed in modules directory.")
            return None

        # Construct the command
        cmd_line = [node_binary, boxjs_script, "--output-dir", box_js_result_dir, file_path]
        self.log('debug', f"[DEBUG] Executing command: {' '.join(cmd_line)}")

        # Run BoxJS with error handling
        try:
            subprocess.run(cmd_line, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        except subprocess.CalledProcessError as e:
            self.log('error', f"[ERROR] BoxJS execution failed: {e}")
            return None

        self.log('debug', "[DEBUG] BoxJS execution completed successfully.")
        return box_js_result_dir, file_sha

    def process_results(self, result_dir, file_sha):
        """ Parses the output of BoxJS and extracts relevant URLs """

        results_file = os.path.join(result_dir, f"{file_sha}-results", "urls.json")

        self.log('debug', f"[DEBUG] Checking for results file: {results_file}")
        if not os.path.exists(results_file):
            self.log('warning', f"[WARNING] No URLs found: {results_file} does not exist.")
            return []

        # Read the URLs
        try:
            with open(results_file, "r", encoding="utf-8") as fd:
                data = json.load(fd)  # Expecting JSON output
                urls = [entry.strip() for entry in data if "http" in entry]

            self.log('debug', f"[DEBUG] Extracted {len(urls)} URLs.")
        except Exception as e:
            self.log('error', f"[ERROR] Failed to read results file: {e}")
            urls = []

        # Cleanup results directory
        shutil.rmtree(result_dir)
        return urls

    def hunter_decode(self, file):
        """ Attempts to decode Hunter-obfuscated JavaScript """
        self.log('debug', f"[DEBUG] Running Hunter decoder on: {file}")
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
        """ Custom logic to decode Hunter obfuscation """
        self.log('debug', "[DEBUG] Running Hunter logic.")
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
        """ Main entry point for the module """
        super(BoxJS, self).run()
        if self.args is None:
            return

        if not __sessions__.is_set():
            self.log('error', "[ERROR] No session opened. This command expects a file to be open.")
            return

        file_path = __sessions__.current.file.path
        file_sha = __sessions__.current.file.sha256

        # Debug: Verify session information
        self.log('debug', f"[DEBUG] File path: {file_path}")
        self.log('debug', f"[DEBUG] File SHA256: {file_sha}")

        # Run BoxJS
        if self.args.box:
            self.log('info', f"[INFO] Running BoxJS on: {file_path} ({file_sha})")
            result_dir, sha = self.run_boxjs(file_path, file_sha)

            if result_dir:
                urls = self.process_results(result_dir, sha)
                if urls:
                    self.log('warning', "[INFO] Extracted URLs:")
                    for url in urls:
                        self.log('info', url)
                else:
                    self.log('info', "[INFO] No URLs extracted from JavaScript file.")

        # Run Hunter decoding
        elif self.args.other:
            try:
                self.log('info', "[INFO] Running Hunter decoder.")
                result = self.hunter_decode(file_path)
                if result:
                    self.log('warning', "[INFO] Decoded JavaScript:")
                    self.log('info', result)
            except Exception as e:
                self.log('error', f"[ERROR] Hunter decoding failed: {e}")

        else:
            self.log('error', "[ERROR] At least one of the parameters is required")
            self.usage()
