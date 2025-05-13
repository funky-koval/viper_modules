#!/usr/bin/env python
# -*- coding: utf-8 -*-
# This file is part of Viper - https://github.com/viper-framework/viper
# See the file 'LICENSE' for copying permission.

"""
Name: sigscan.py
Author: Generated for Viper Framework
Version: 1.0

Description: Scans files for common file signatures (magic bytes) to identify file types
             and potentially detect hidden or embedded files.

Man-style help:
    Usage: sigscan [options]
    
    Options:
        --scan       Scan file for common file signatures and show matches
        --detailed   Scan with detailed signature information (includes description)
        --all        Show all signatures in the database
        
    Examples:
        viper > sigscan --scan
        [+] Found signature at offset 0: PDF Document (25 50 44 46)
        [+] Found signature at offset 1024: ZIP Archive (50 4B 03 04)
        
        viper > sigscan --detailed
        [+] Found signature at offset 0: PDF Document (25 50 44 46)
            Description: Portable Document Format file
            Extension: .pdf
"""

import os
import re
from viper.common.abstracts import Module
from viper.core.session import __sessions__

class SigScan(Module):
    cmd = 'sigscan'
    description = 'Scan files for common file signatures (magic bytes)'
    authors = ['Viper Framework Module Generator']
    categories = ['analysis', 'binary']
    
    def __init__(self):
        super(SigScan, self).__init__()
        # Define command-line arguments as single-purpose flags
        self.parser.add_argument('--scan', action='store_true', help='Scan for file signatures')
        self.parser.add_argument('--detailed', action='store_true', help='Show detailed signature information')
        self.parser.add_argument('--all', action='store_true', help='List all known signatures')
        
        # Initialize the signature database
        # Format: (signature bytes, name, description, extension)
        self.signatures = [
            # Document formats
            (b'\x25\x50\x44\x46', 'PDF Document', 'Portable Document Format file', '.pdf'),
            (b'\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1', 'MS Office Document', 'OLE Compound Document Format', '.doc/.xls/.ppt'),
            (b'\x50\x4B\x03\x04', 'ZIP Archive', 'ZIP compressed archive', '.zip/.docx/.xlsx/.pptx'),
            (b'\x50\x4B\x05\x06', 'ZIP Archive (Empty)', 'ZIP archive (empty)', '.zip'),
            (b'\x50\x4B\x07\x08', 'ZIP Archive (Spanned)', 'ZIP archive (spanned)', '.zip'),
            
            # Images
            (b'\xFF\xD8\xFF', 'JPEG Image', 'JPEG/JFIF image format', '.jpg/.jpeg'),
            (b'\x89\x50\x4E\x47\x0D\x0A\x1A\x0A', 'PNG Image', 'Portable Network Graphics image', '.png'),
            (b'\x47\x49\x46\x38', 'GIF Image', 'Graphics Interchange Format image', '.gif'),
            (b'\x42\x4D', 'BMP Image', 'Windows Bitmap image', '.bmp'),
            
            # Executables
            (b'\x4D\x5A', 'PE Executable', 'Windows/DOS executable (MZ header)', '.exe/.dll/.sys'),
            (b'\x7F\x45\x4C\x46', 'ELF File', 'Linux/Unix Executable and Linkable Format', ''),
            
            # Audio/Video
            (b'\x52\x49\x46\x46', 'RIFF Format', 'Audio/Video container (WAV/AVI)', '.wav/.avi'),
            (b'\x66\x74\x79\x70', 'ISO Media File', 'MP4/QuickTime container', '.mp4/.mov/.m4a'),
            (b'\x49\x44\x33', 'MP3 Audio (with ID3)', 'MP3 audio with ID3 metadata', '.mp3'),
            (b'\xFF\xFB', 'MP3 Audio', 'MP3 audio without ID3', '.mp3'),
            
            # Archives
            (b'\x52\x61\x72\x21\x1A\x07', 'RAR Archive', 'RAR compressed archive v1.5+', '.rar'),
            (b'\x37\x7A\xBC\xAF\x27\x1C', '7-Zip Archive', '7-Zip compressed archive', '.7z'),
            (b'\x1F\x8B', 'GZip Archive', 'GZip compressed archive', '.gz'),
            (b'\x42\x5A\x68', 'BZip2 Archive', 'BZip2 compressed archive', '.bz2'),
            
            # Misc
            (b'\x00\x61\x73\x6D', 'WebAssembly Binary', 'WebAssembly binary format', '.wasm'),
            (b'\x7B\x5C\x72\x74\x66', 'RTF Document', 'Rich Text Format document', '.rtf'),
            (b'\x23\x21', 'Shell Script', 'Unix shell script (shebang)', '.sh'),
            (b'\x43\x57\x53', 'Flash SWF', 'Adobe Flash SWF file (uncompressed)', '.swf'),
            (b'\x46\x57\x53', 'Flash SWF', 'Adobe Flash SWF file (compressed)', '.swf'),
            (b'\x1F\x9D', 'Compressed File', 'Compressed file using LZW compression', '.Z'),
            (b'\x1F\xA0', 'Compressed File', 'Compressed file using LZH compression', '.z/.lha'),
            (b'\x3C\x3F\x78\x6D\x6C', 'XML Document', 'XML Document or fragment', '.xml'),
            (b'\x21\x3C\x61\x72\x63\x68\x3E', 'Debian Package', 'Linux Debian package', '.deb'),
        ]

    def _find_signatures(self, data, detailed=False):
        """
        Scans the binary data for file signatures and returns matches.
        
        Args:
            data (bytes): The file data to scan
            detailed (bool): Whether to include detailed descriptions
            
        Returns:
            list: List of tuples containing (offset, signature_info)
        """
        results = []
        
        # Scan through the entire file
        for i in range(len(data)):
            for sig, name, desc, ext in self.signatures:
                # Check if we have enough data left to match the signature
                if i + len(sig) <= len(data):
                    # If the bytes at the current position match the signature
                    if data[i:i+len(sig)] == sig:
                        hex_sig = ' '.join([f'{byte:02X}' for byte in sig])
                        
                        # Create result entry based on detail level
                        if detailed:
                            result = {
                                'offset': i,
                                'name': name,
                                'hex': hex_sig,
                                'description': desc,
                                'extension': ext
                            }
                        else:
                            result = {
                                'offset': i,
                                'name': name,
                                'hex': hex_sig
                            }
                        
                        results.append(result)
        
        return results

    def _list_all_signatures(self):
        """
        Lists all signatures in the database with their details.
        """
        header = ['Signature', 'File Type', 'Description', 'Extension(s)']
        rows = []
        
        for sig, name, desc, ext in self.signatures:
            hex_sig = ' '.join([f'{byte:02X}' for byte in sig])
            rows.append([hex_sig, name, desc, ext])
        
        self.log('table', {'header': header, 'rows': rows})

    def run(self):
        """
        Main method for running the module functionality.
        Handles argument parsing and function dispatch.
        """
        args = self.parser.parse_args(self.args)
        
        # List all known signatures
        if args.all:
            self.log('info', f'Listing all {len(self.signatures)} known file signatures:')
            self._list_all_signatures()
            return
        
        # Check if a file is loaded in the current session
        if not __sessions__.is_set():
            self.log('error', 'No file is currently loaded. Use the "open" command first.')
            return
        
        # Get the current file's path
        file_path = __sessions__.current.file.path
        
        # Show basic file information
        file_size = os.path.getsize(file_path)
        self.log('info', f'Scanning file: {os.path.basename(file_path)} ({file_size:,} bytes)')
        
        # Read the file content
        with open(file_path, 'rb') as f:
            data = f.read()
        
        # Scan for file signatures with basic or detailed output
        if args.scan or args.detailed:
            self.log('info', 'Scanning for file signatures...')
            results = self._find_signatures(data, detailed=args.detailed)
            
            if not results:
                self.log('warning', 'No file signatures were detected in the current file.')
                return
            
            self.log('success', f'Found {len(results)} signature matches.')
            
            # Display the results in a table format
            if args.detailed:
                header = ['Offset', 'File Type', 'Signature', 'Description', 'Extension']
                rows = []
                for r in results:
                    rows.append([
                        f'0x{r["offset"]:08X}', 
                        r["name"], 
                        r["hex"], 
                        r["description"], 
                        r["extension"]
                    ])
            else:
                header = ['Offset', 'File Type', 'Signature']
                rows = []
                for r in results:
                    rows.append([
                        f'0x{r["offset"]:08X}', 
                        r["name"], 
                        r["hex"]
                    ])
            
            self.log('table', {'header': header, 'rows': rows})
            
            # Provide a summary of unique file types found
            file_types = set(r["name"] for r in results)
            summary = ", ".join(sorted(file_types))
            self.log('info', f'Summary of file types detected: {summary}')
            
            # Check for interesting patterns
            embedded_offset = [r for r in results if r["offset"] > 0]
            if embedded_offset:
                self.log('warning', f'Found {len(embedded_offset)} potential embedded file(s).')
                self.log('info', 'To extract embedded content, consider using the "carver" module (if available).')
        else:
            self.log('error', 'No action requested. Please specify --scan, --detailed, or --all.')
            self.usage()

    def usage(self):
        """
        Show usage information when the module is invoked without arguments.
        """
        self.log('info', 'Usage: sigscan [--scan|--detailed|--all]')
        self.log('info', '  --scan      : Scan file for common file signatures')
        self.log('info', '  --detailed  : Scan with detailed signature information')
        self.log('info', '  --all       : List all known signatures in the database')
