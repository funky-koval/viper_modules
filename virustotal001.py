import tempfile
import viperconf
from viper.common.out import bold
from viper.common.abstracts import Module
from viper.core.session import __sessions__

try:
    import requests
    HAVE_REQUESTS = True
except ImportError:
    HAVE_REQUESTS = False

VIRUSTOTAL_URL = viperconf.VIRUSTOTAL_URL
VIRUSTOTAL_URL_SUBMIT = viperconf.VIRUSTOTAL_URL_SUBMIT
VIRUSTOTAL_URL_DOWNLOAD = viperconf.VIRUSTOTAL_URL_DOWNLOAD
VIRUSTOTAL_URL_COMMENT = viperconf.VIRUSTOTAL_URL_COMMENT
KEY = viperconf.VIRUSTOTAL_KEY

class VirusTotal(Module):
    cmd = 'virustotal'
    description = 'Lookup the file on VirusTotal'
    authors = ['']

    def __init__(self):
        super().__init__()
        self.parser.add_argument('-s', '--submit', action='store_true',
                                 help='Submit file to VirusTotal (default is lookup by hash only)')
        self.parser.add_argument('-d', '--download', action='store', dest='hash')
        self.parser.add_argument('-c', '--comment', nargs='+', action='store', dest='comment')

    def run(self):
        super().run()
        if not self.args:
            return

        if self.args.hash:
            self._download_file(self.args.hash)

        if not HAVE_REQUESTS:
            self.log('error', "Missing dependency, install requests (`pip install requests`)")
            return

        if not __sessions__.is_set():
            self.log('error', "No session opened")
            return

        self._lookup()

        if self.args.submit:
            self._submit_file()

        if self.args.comment:
            self._submit_comment()

    def _download_file(self, hash_value):
        try:
            params = {'apikey': KEY, 'hash': hash_value}
            response = requests.get(VIRUSTOTAL_URL_DOWNLOAD, params=params)

            if response.status_code == 403:
                self.log('error', 'Invalid API key or insufficient permissions')
                return

            if response.status_code == 200:
                tmp = tempfile.NamedTemporaryFile(delete=False)
                tmp.write(response.content)
                tmp.close()
                __sessions__.new(tmp.name)
        except Exception as e:
            self.log('error', f"Failed to download file: {e}")

    def _lookup(self):
        data = {'resource': __sessions__.current.file.md5, 'apikey': KEY}
        try:
            response = requests.post(VIRUSTOTAL_URL, data=data)
            virustotal = self._parse_response(response)
            if virustotal is None:
                return
        except Exception as e:
            self.log('error', f"Failed performing request: {e}")
            return

        rows = []
        scans = virustotal.get('scans', {})
        for engine, signature in scans.items():
            sig = signature['result'] if signature.get('detected') else ''
            rows.append((engine, sig))

        rows.sort()
        if rows:
            self.log('info', "VirusTotal Report:")
            self.log('table', dict(header=['Antivirus', 'Signature'], rows=rows))
            if self.args.submit:
                self.log('info', "File is already on VirusTotal, skipping submission")
        else:
            self.log('info', "File not found on VirusTotal")

        if 'verbose_msg' in virustotal:
            self.log('info', f"{bold('VirusTotal message')} {virustotal['verbose_msg']}")

    def _submit_file(self):
        try:
            data = {'apikey': KEY}
            files = {'file': open(__sessions__.current.file.path, 'rb')}
            response = requests.post(VIRUSTOTAL_URL_SUBMIT, data=data, files=files)
            virustotal = self._parse_response(response)
            if virustotal and 'verbose_msg' in virustotal:
                self.log('info', f"{bold('VirusTotal message')} {virustotal['verbose_msg']}")
        except Exception as e:
            self.log('error', f"Failed Submit: {e}")

    def _submit_comment(self):
        try:
            data = {
                'apikey': KEY,
                'resource': __sessions__.current.file.md5,
                'comment': ' '.join(self.args.comment)
            }
            response = requests.post(VIRUSTOTAL_URL_COMMENT, data=data)
            virustotal = self._parse_response(response)
            if virustotal and 'verbose_msg' in virustotal:
                self.log('info', f"{bold('VirusTotal message')} {virustotal['verbose_msg']}")
        except Exception as e:
            self.log('error', f"Failed Submit Comment: {e}")

    def _parse_response(self, response):
        try:
            return response.json()
        except Exception as e:
            # Python 2.7 workaround
            if str(e) == "'dict' object is not callable":
                try:
                    return response.json
                except Exception as e2:
                    self.log('error', f"Failed parsing response: {e2}")
                    self.log('error', f"Data:\n{response.content}")
                    return None
            self.log('error', f"Failed parsing response: {e}")
            self.log('error', f"Data:\n{response.content}")
            return None
