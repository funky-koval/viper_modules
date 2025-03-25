import os
import base64
import requests
import viperconf
import urllib3

from viper.common.abstracts import Module
from viper.core.session import __sessions__

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

vmray_url = viperconf.vmray_url
submit_file_api = viperconf.vmray_url_submit
vmray_api_key = viperconf.vmray_api_key

class VMRay(Module):
    cmd = 'vmray'
    description = 'Submit the file to VMRay POC Sandbox'
    authors = []

    def __init__(self):
        super().__init__()
        self.parser.add_argument('-s', '--submit', action='store_true', help='Submit Sample to VMRay Sandbox')
        self.parser.add_argument('-d', '--download', dest='vmrayid', help='Download VMRay Report by ID (Not implemented)')

    def submit(self, filename, sample_path):
        headers = {"Authorization": f"api_key {vmray_api_key}"}

        try:
            with open(sample_path, "rb") as f:
                file_data = f.read()
        except Exception as e:
            self.log('error', f"Failed to read sample file: {e}")
            return None

        req_params = {
            "sample_filename_b64enc": base64.b64encode(filename.encode("utf-8")).decode("utf-8"),
            "analyzer_mode": "reputation_static_dynamic"
        }

        file_params = {"sample_file": file_data}

        try:
            response = requests.post(
                vmray_url + submit_file_api,
                params=req_params,
                headers=headers,
                files=file_params,
                verify=False
            )
        except requests.RequestException as e:
            self.log('error', f"Request to VMRay failed: {e}")
            return None

        try:
            json_result = response.json()
        except ValueError:
            self.log('error', f"API returned invalid JSON: {response.text}")
            return None

        return json_result.get("data")

    def run(self):
        super().run()

        if self.args is None:
            return

        if not __sessions__.is_set():
            self.log("error", "No session opened")
            return

        if self.args.submit:
            sample_path = __sessions__.current.file.path
            filename = __sessions__.current.file.name
            result = self.submit(filename, sample_path)

            if not result:
                self.log("error", "Submission failed or returned no data")
                return

            submissions = result.get("submissions")
            if not submissions:
                self.log("info", "No reports for opened file")
                return

            rows = sorted([[tag, detail] for tag, detail in submissions[0].items()])
            self.log("info", "VMRay Submission:")
            self.log("table", dict(header=['Tag', 'Details'], rows=rows))
