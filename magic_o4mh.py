import os
from viper.common.abstracts import Module
from viper.core.session import __sessions__

class Sigscan(Module):
    cmd = 'sigscan'
    description = 'Scan file for common file signatures and display matches'
    authors = ['Assistant Name']
    categories = ['analysis', 'file']

    def __init__(self):
        super(Sigscan, self).__init__()
        # Optional flag: display offsets in hexadecimal
        self.parser.add_argument(
            '--hex', 
            action='store_true', 
            help='Display offsets in hexadecimal'
        )

    def run(self):
        # Parse CLI arguments
        args = self.parser.parse_args(self.args)

        # Ensure a file is loaded in the current session
        if not __sessions__.is_set():
            self.log('error', 'No file is currently loaded. Use the "open" command first.')
            return

        # Read the loaded file into memory
        file_path = __sessions__.current.file.path
        try:
            with open(file_path, 'rb') as f:
                data = f.read()
        except Exception as e:
            self.log('error', f'Could not read file: {e}')
            return

        # Define common magic bytes signatures
        signatures = {
            b'\x89PNG\r\n\x1a\n': 'PNG Image',
            b'\xff\xd8\xff': 'JPEG Image',
            b'%PDF-': 'PDF Document',
            b'PK\x03\x04': 'ZIP Archive',
            b'Rar!\x1a\x07\x00': 'RAR Archive',
            b'MZ': 'Windows Executable (PE)',
            b'\x7fELF': 'ELF Executable',
            b'\x25\x21PS-Adobe-': 'PostScript Document',
            b'GIF87a': 'GIF Image (87a)',
            b'GIF89a': 'GIF Image (89a)',
        }

        matches = []

        # Scan for each signature in the file
        for magic, name in signatures.items():
            start = 0
            while True:
                idx = data.find(magic, start)
                if idx == -1:
                    break
                matches.append((idx, name))
                start = idx + 1  # continue searching after this match

        if not matches:
            self.log('warning', 'No known signatures found in the file.')
            return

        # Prepare table rows
        rows = []
        for offset, filetype in matches:
            if args.hex:
                offset_str = hex(offset)
            else:
                offset_str = str(offset)
            rows.append([offset_str, filetype])

        # Log the results in a table
        self.log('table', {
            'header': ['Offset', 'File Type'],
            'rows': rows
        })
        self.log('success', f'Found {len(matches)} signature match(es).')
