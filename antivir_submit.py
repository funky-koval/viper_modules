# -*- coding: utf-8 -*-
import os
import mimetypes
import datetime
import base64
import requests

from viper.common.abstracts import Module
from viper.core.session import __sessions__
from viper.common.utils import send_email
import viperconf

class EmailSender:
    submit_email = None
    subject = "Malware detection"
    cfg_key = None

    def __init__(self, email_body):
        self._email_body = email_body
        self._cfg = viperconf.email_data[self.cfg_key]

    def submit(self, file):
        send_email(
            to_address=self.submit_email,
            subject=self.subject,
            msg_body=self._email_body,
            attachments=[file],
            cfg=self._cfg
        )

    @property
    def body(self):
        return self._email_body

class McafeeEmailSender(EmailSender):
    cfg_key = "outlook"
    submit_email = ["virus_research@avertlabs.com"]

class McafeeEmailSenderBackup(EmailSender):
    cfg_key = "gmail"
    submit_email = ["virus_research@avertlabs.com"]

class SophosEmailSender(EmailSender):
    cfg_key = "gmail"
    submit_email = ["samples@sophos.com"]

class SophosEmailSenderBackup(EmailSender):
    cfg_key = "outlook"
    submit_email = ["samples@sophos.com"]

class AVSubmit(Module):
    cmd = 'avsubmit'
    description = "Submit the file to AV vendors for inclusion in detections."

    def __init__(self):
        super().__init__()
        self.parser.add_argument("--symantec", action="store_true", help="Submit the file to Symantec")
        self.parser.add_argument("--mcafee", action="store_true", help="Submit the file to McAfee")
        self.parser.add_argument("--sophos", action="store_true", help="Submit the file to Sophos")
        self.parser.add_argument("--all", action="store_true", help="Submit the file to all vendors")
        self.parser.add_argument("--email_body", default="", help="Body of the email message")
        self._email_body = None

    def run(self):
        super().run()

        if self.args is None:
            return

        self._email_body = base64.b64decode(self.args.email_body).decode(errors='ignore') if self.args.email_body else ""

        if not __sessions__.is_set():
            self.log("error", "No session opened")
            return

        if not os.path.exists(__sessions__.current.file.path):
            self.log("error", "Session file does not exist")
            return

        file_path = __sessions__.current.file.path
        self.log("info", f"Submitted file: {file_path}")

        if self.args.symantec:
            self.symantec_submit(file_path)
        if self.args.mcafee:
            self.mcafee_submit(file_path)
        if self.args.sophos:
            self.sophos_submit(file_path)
        if self.args.all:
            self.symantec_submit(file_path)
            self.mcafee_submit(file_path)
            self.sophos_submit(file_path)
        if not any([self.args.symantec, self.args.mcafee, self.args.sophos, self.args.all]):
            self.log("error", "At least one of the parameters is required")
            self.usage()

    def symantec_submit(self, file):
        url = viperconf.symantec_submission_url2
        auth = base64.b64encode(f"{viperconf.symantec_submission_username}:{viperconf.symantec_submission_password}".encode()).decode()
        headers = {
            'Authorization': f"Basic {auth}",
            'Content-Type': 'multipart/form-data'
        }
        data = {
            'contactEmailAddress': viperconf.email_address,
            'sample': file,
            'emailNotifications': 'false'
        }
        try:
            res = requests.post(url, data=data, headers=headers, verify=False)
            self.log("info", f"Submission to Symantec successful at {datetime.datetime.now()}" if res.ok else f"Failed submission to Symantec")
        except Exception as e:
            self.log("error", f"Symantec submission failed: {e}")

    def mcafee_submit(self, file):
        try:
            sender = McafeeEmailSender(self._email_body)
            sender.submit(file)
            self.log("info", f"Submission to McAfee successful at {datetime.datetime.now()}")
        except Exception as e:
            self.log("info", f"McAfee submission error: {e}, trying backup")
            try:
                sender = McafeeEmailSenderBackup(self._email_body)
                sender.submit(file)
                self.log("info", f"Backup submission to McAfee successful at {datetime.datetime.now()}")
            except Exception as ex:
                self.log("info", f"Backup McAfee submission failed: {ex}")

    def sophos_submit(self, file):
        try:
            sender = SophosEmailSender(self._email_body)
            sender.submit(file)
            self.log("info", f"Submission to Sophos successful at {datetime.datetime.now()}")
        except Exception as e:
            self.log("info", f"Sophos submission error: {e}, trying backup")
            try:
                sender = SophosEmailSenderBackup(self._email_body)
                sender.submit(file)
                self.log("info", f"Backup submission to Sophos successful at {datetime.datetime.now()}")
            except Exception as ex:
                self.log("info", f"Backup Sophos submission failed: {ex}")
