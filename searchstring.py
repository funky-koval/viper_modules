# -*- coding: utf-8 -*-
# Example Viper module: Search for a string in the loaded file

import os

from viper.common.abstracts import Module
from viper.core.session import __sessions__


class StringSearch(Module):
    cmd = 'searchstring'
    description = 'Search for a string in the currently loaded file'
    authors = ['Analyst Name']
    categories = ['string', 'example']

    def __init__(self):
        super(StringSearch, self).__init__()
        self.parser.add_argument('-s', '--search', required=True, help='String to search for in the file')

    def run(self):
        # Check if a file is open in the session
        if not __sessions__.is_set():
            self.log('error', 'No file is currently loaded. Use the "open" command first.')
            return

        args = self.parser.parse_args(self.args)
        search_term = args.search.encode('utf-8')  # Convert to bytes for binary search

        file_path = __sessions__.current.file.path
        self.log('info', f'Searching for "{args.search}" in {__sessions__.current.file.name}')

        try:
            with open(file_path, 'rb') as f:
                data = f.read()

            # Find all matches and their offsets
            matches = []
            offset = data.find(search_term)
            while offset != -1:
                matches.append(offset)
                offset = data.find(search_term, offset + 1)

            if matches:
                self.log('success', f'Found {len(matches)} occurrence(s) of "{args.search}":')
                for idx, match_offset in enumerate(matches):
                    self.log('item', f'Match {idx+1}: Offset {match_offset}')
            else:
                self.log('warning', f'No matches found for "{args.search}".')

        except Exception as e:
            self.log('error', f'Error reading file: {str(e)}')
