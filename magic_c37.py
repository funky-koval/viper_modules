#!/usr/bin/env python
# -*- coding: utf-8 -*-
# This file is part of Viper - https://github.com/viper-framework/viper
# See the file 'LICENSE' for copying permission.

import os
import re
import binascii
from collections import OrderedDict

from viper.common.abstracts import Module
from viper.core.session import sessions

class MagicBytes(Module):
    cmd = 'magicbytes'
    description = 'Scan file for known file signatures (magic bytes) at any offset'
    authors = ['Claude 3.7 Sonnet']
    categories = ['analysis', 'identification']

    def __init__(self):
        super(MagicBytes, self).__init__()
        self.parser.add_argument('--all', action='store_true', help='Show all matches including overlapping ones')
        self.parser.add_argument('--min-size', type=int, default=0, help='Minimum file size to report (in bytes)')
        self.parser.add_argument('--category', help='Only show signatures from specified category')
        self.parser.add_argument('--json', action='store_true', help='Output results in JSON format')
        
        # Dictionary of file signatures
        # Format: 'Signature': ('File Type', 'Category', Min Size in bytes)
        self.signatures = OrderedDict([
            # Archives
            (b'PK\x03\x04', ('ZIP Archive', 'archive', 50)),
            (b'Rar!\x1a\x07\x00', ('RAR Archive (v1.5+)', 'archive', 50)),
            (b'Rar!\x1a\x07\x01\x00', ('RAR Archive (v5+)', 'archive', 50)),
            (b'\x37\x7A\xBC\xAF\x27\x1C', ('7-Zip Archive', 'archive', 50)),
            (b'\x1F\x8B\x08', ('GZIP Archive', 'archive', 20)),
            
            # Office Documents
            (b'\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1', ('MS Office/OLE2 Document', 'document', 1000)),
            (b'PK\x03\x04\x14\x00\x06\x00', ('MS Office 2007+ Document', 'document', 1000)),
            (b'\xEC\xA5\xC1\x00', ('MS Word Document', 'document', 1000)),
            
            # PDF
            (b'%PDF', ('PDF Document', 'document', 100)),
            
            # Executables
            (b'MZ', ('PE Executable', 'executable', 100)),
            (b'\x7FELF', ('ELF Executable', 'executable', 100)),
            (b'\xCA\xFE\xBA\xBE', ('Mach-O Executable (Universal/Fat)', 'executable', 100)),
            (b'\xCF\xFA\xED\xFE', ('Mach-O Executable (x86 64-bit)', 'executable', 100)),
            (b'\xCE\xFA\xED\xFE', ('Mach-O Executable (x86 32-bit)', 'executable', 100)),
            (b'\xFE\xED\xFA\xCE', ('Mach-O Executable (PPC 32-bit)', 'executable', 100)),
            (b'\xFE\xED\xFA\xCF', ('Mach-O Executable (PPC 64-bit)', 'executable', 100)),
            
            # Scripts
            (b'#!/', ('Shell Script', 'script', 10)),
            (b'<?php', ('PHP Script', 'script', 10)),
            
            # Images
            (b'\xFF\xD8\xFF', ('JPEG Image', 'image', 100)),
            (b'\x89PNG\r\n\x1A\n', ('PNG Image', 'image', 100)),
            (b'GIF8', ('GIF Image', 'image', 100)),
            (b'BM', ('BMP Image', 'image', 100)),
            (b'II*\x00', ('TIFF Image (little-endian)', 'image', 100)),
            (b'MM\x00*', ('TIFF Image (big-endian)', 'image', 100)),
            (b'\x00\x00\x01\x00', ('ICO Image', 'image', 30)),
            
            # Media
            (b'\x52\x49\x46\x46', ('RIFF Container (AVI/WAV)', 'media', 100)),
            (b'\x1A\x45\xDF\xA3', ('EBML/Matroska/WebM', 'media', 100)),
            (b'\x00\x00\x00\x14\x66\x74\x79\x70', ('MP4 Video', 'media', 100)),
            (b'\x49\x44\x33', ('MP3 Audio (with ID3)', 'media', 100)),
            (b'\xFF\xFB', ('MP3 Audio', 'media', 100)),
            (b'OggS', ('Ogg Vorbis Audio', 'media', 100)),
            (b'fLaC', ('FLAC Audio', 'media', 100)),
            
            # Certificates and Crypto
            (b'-----BEGIN CERTIFICATE-----', ('PEM Certificate', 'crypto', 30)),
            (b'-----BEGIN RSA PRIVATE KEY-----', ('PEM RSA Private Key', 'crypto', 30)),
            (b'-----BEGIN PRIVATE KEY-----', ('PEM Private Key', 'crypto', 30)),
            (b'-----BEGIN PUBLIC KEY-----', ('PEM Public Key', 'crypto', 30)),
            (b'ssh-rsa', ('SSH RSA Public Key', 'crypto', 30)),
            (b'ssh-dss', ('SSH DSA Public Key', 'crypto', 30)),
            
            # Virtual Machines & Containers
            (b'\x7F\x45\x4C\x46\x02\x01\x01', ('Linux ELF 64-bit', 'executable', 100)),
            (b'\x7F\x45\x4C\x46\x01\x01\x01', ('Linux ELF 32-bit', 'executable', 100)),
            (b'KDMV', ('VMware Disk File', 'virtual', 100)),
            (b'\x4F\x52\x43\x4D', ('Oracle VM VirtualBox Disk Image', 'virtual', 100)),
            
            # Disk Images
            (b'\x78\x01\x73\x0D\x62\x62\x60', ('DMG Disk Image', 'disk', 100)),
            (b'\x63\x82\x01\x00', ('DHCP/BOOTP Message', 'network', 100)),
            
            # Database
            (b'SQLite format 3\x00', ('SQLite Database', 'database', 100)),
            (b'\xFE\xE7\x01\x00', ('MS Access Database', 'database', 1000)),
            
            # Memory Dumps
            (b'MDMP', ('Windows Minidump File', 'memory', 1000)),
            (b'PMDM', ('QEMU Memory Dump', 'memory', 1000)),
            
            # Malware Specific
            (b'TV\x12\xAF', ('TinyV Compiler Output', 'malware', 100)),
            (b'MZ\x90\x00\x03\x00\x00\x00', ('Potential Packed Executable', 'malware', 100)),
            
            # Encryption & Compressed
            (b'\x47\x01\x00\x00\x00\xFF\xFF\x03\x00\x00\x00', ('UPX Packed Data', 'packed', 100)),
            (b'\xFC\x4D\x4D\x4D\x00\x00\x00\x00', ('SZDD Compressed File', 'compressed', 100)),
            (b'\x53\x5A\x44\x44\x88\xF0\x27\x33', ('SZDD Compressed System File', 'compressed', 100)),
            
            # Mobile
            (b'dex\n', ('Android DEX File', 'mobile', 100)),
            (b'PK\x03\x04\x14\x00\x08\x00\x08\x00', ('APK File', 'mobile', 100)),
            (b'\xCA\xFE\xBA\xBE\x00\x00\x00', ('Java Class File', 'mobile', 100)),
            
            # Other
            (b'\x00\x61\x73\x6D', ('WebAssembly Binary', 'web', 20)),
            (b'\x7B\x5C\x72\x74', ('Rich Text Format', 'document', 30))
        ])

    def search_signatures(self, data, min_size=0, category=None, all_matches=False):
        """
        Search for file signatures within binary data
        
        Args:
            data (bytes): Binary data to scan
            min_size (int): Minimum file size to report
            category (str): Only show signatures from specified category
            all_matches (bool): If True, show all matches including overlapping ones
        
        Returns:
            list: List of tuples (offset, signature, file_type, category, min_size)
        """
        results = []
        
        # Loop through all signatures
        for signature, (file_type, sig_category, sig_min_size) in self.signatures.items():
            # Skip if category filter is set and doesn't match
            if category and category.lower() != sig_category.lower():
                continue
                
            # Skip if minimum size filter is greater than this signature's minimum
            if min_size > sig_min_size:
                continue
                
            # Find all occurrences of the signature
            offset = 0
            while True:
                offset = data.find(signature, offset)
                if offset == -1:
                    break
                    
                results.append((offset, signature, file_type, sig_category, sig_min_size))
                
                # Move past this signature to find the next one
                offset += len(signature)
                
                # Break after first match if not searching for all matches
                if not all_matches:
                    break
        
        # Sort results by offset
        return sorted(results, key=lambda x: x[0])

    def format_bytes(self, byte_str):
        """Format binary signature as hex for display"""
        return binascii.hexlify(byte_str).decode('utf-8')
    
    def run(self):
        args = self.parser.parse_args(self.args)
        
        # Check if a session is active
        if not sessions.is_set():
            self.log('error', 'No file is currently loaded. Use the "open" command first.')
            return
            
        try:
            # Read the currently loaded file
            file_path = sessions.current.file.path
            with open(file_path, 'rb') as f:
                data = f.read()
                
            self.log('info', f'Scanning {len(data):,} bytes for file signatures...')
            
            # Search for signatures
            results = self.search_signatures(
                data,
                min_size=args.min_size,
                category=args.category,
                all_matches=args.all
            )
            
            if not results:
                self.log('warning', 'No file signatures found in the current file.')
                return
                
            # Format and display results
            if args.json:
                # JSON output
                json_results = []
                for offset, signature, file_type, category, min_size in results:
                    json_results.append({
                        'offset': offset,
                        'offset_hex': hex(offset),
                        'signature': self.format_bytes(signature),
                        'file_type': file_type,
                        'category': category,
                        'potential_size': len(data) - offset
                    })
                self.log('info', {'results': json_results})
            else:
                # Table output
                header = ['Offset', 'Hex Offset', 'Signature', 'File Type', 'Category', 'Potential Size']
                rows = []
                
                for offset, signature, file_type, category, min_size in results:
                    rows.append([
                        f"{offset:,}",
                        f"{hex(offset)}",
                        self.format_bytes(signature),
                        file_type,
                        category,
                        f"{len(data) - offset:,} bytes"
                    ])
                
                self.log('table', {'header': header, 'rows': rows})
                self.log('success', f'Found {len(results)} file signature(s)')
                
                if not args.all and len(results) > 0:
                    self.log('info', 'Note: Only showing first occurrence of each signature. Use --all to show all matches.')
                
        except Exception as e:
            self.log('error', f'Error scanning file: {str(e)}')
