#!/usr/bin/env python3
"""
FileSignatures Viper Module

This module scans the loaded file for common file signatures (magic bytes)
and displays all matches with their byte offset and file type.

Usage:
    > filesignatures --scan      # Scan file for all signatures
    > filesignatures --deep      # Perform deeper scan (slower but more thorough)
    > filesignatures --export    # Export findings to a JSON file

Sample output:
    [*] Scanning for file signatures...
    [+] Found 3 file signatures:
    +--------+----------+----------------+------------------------+
    | Offset | Hex Sig  | File Type      | Description            |
    +--------+----------+----------------+------------------------+
    | 0      | 504B0304 | ZIP            | ZIP archive            |
    | 3450   | FFD8FF   | JPEG           | JPEG image file        |
    | 12788  | 7F454C46 | ELF            | Linux executable       |
    +--------+----------+----------------+------------------------+
"""

import os
import json
import binascii
from viper.common.abstracts import Module
from viper.core.session import __sessions__

class FileSignatures(Module):
    cmd = 'filesignatures'
    description = 'Scan files for common file signatures (magic bytes)'
    authors = ['Viper Team']
    categories = ['analysis', 'binary']
    
    def __init__(self):
        super(FileSignatures, self).__init__()
        self.parser.add_argument('--scan', action='store_true', help='Scan file for all signatures')
        self.parser.add_argument('--deep', action='store_true', help='Perform deeper scan (slower but more thorough)')
        self.parser.add_argument('--export', action='store_true', help='Export findings to a JSON file')
        
        # Initialize the signature database with common file signatures
        # Format: {hex_signature: (name, description)}
        self.signatures = {
            # Archive formats
            b'\x50\x4B\x03\x04': ('ZIP', 'ZIP archive'),
            b'\x50\x4B\x05\x06': ('ZIP', 'ZIP archive (empty)'),
            b'\x50\x4B\x07\x08': ('ZIP', 'ZIP archive (spanned)'),
            b'\x52\x61\x72\x21\x1A\x07': ('RAR', 'RAR archive v1.5+'),
            b'\x52\x61\x72\x21\x1A\x07\x00': ('RAR', 'RAR archive v5+'),
            b'\x1F\x8B\x08': ('GZIP', 'GZIP compressed file'),
            b'\x42\x5A\x68': ('BZIP2', 'BZIP2 compressed file'),
            b'\x37\x7A\xBC\xAF\x27\x1C': ('7Z', '7-Zip archive'),
            
            # Executable formats
            b'\x4D\x5A': ('PE', 'Windows/DOS executable'),
            b'\x7F\x45\x4C\x46': ('ELF', 'Linux executable'),
            b'\xCF\xFA\xED\xFE': ('MACHO', 'Mach-O binary (32-bit)'),
            b'\xCE\xFA\xED\xFE': ('MACHO', 'Mach-O binary (64-bit)'),
            b'\xCA\xFE\xBA\xBE': ('JAVA', 'Java class file or Mach-O FAT binary'),
            
            # Document formats
            b'\x25\x50\x44\x46': ('PDF', 'PDF document'),
            b'\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1': ('MS_OFFICE', 'Microsoft Office document'),
            b'\x50\x4B\x03\x04\x14\x00\x06\x00': ('DOCX', 'MS Office Open XML Format'),
            b'\x3C\x3F\x78\x6D\x6C\x20': ('XML', 'XML document'),
            
            # Image formats
            b'\xFF\xD8\xFF': ('JPEG', 'JPEG image file'),
            b'\x89\x50\x4E\x47\x0D\x0A\x1A\x0A': ('PNG', 'PNG image file'),
            b'\x47\x49\x46\x38\x37\x61': ('GIF', 'GIF image file (87a)'),
            b'\x47\x49\x46\x38\x39\x61': ('GIF', 'GIF image file (89a)'),
            b'\x42\x4D': ('BMP', 'BMP image file'),
            b'\x49\x49\x2A\x00': ('TIFF', 'TIFF image file (little-endian)'),
            b'\x4D\x4D\x00\x2A': ('TIFF', 'TIFF image file (big-endian)'),
            
            # Audio/Video formats
            b'\x52\x49\x46\x46': ('RIFF', 'RIFF container (AVI, WAV)'),
            b'\x66\x74\x79\x70': ('MP4', 'MP4 video file'),
            b'\x1A\x45\xDF\xA3': ('WEBM', 'WebM video file'),
            b'\x49\x44\x33': ('MP3', 'MP3 audio file'),
            b'\x4F\x67\x67\x53': ('OGG', 'OGG audio file'),
            
            # Other formats
            b'\x1F\x8B': ('GZIP', 'GZIP compressed file'),
            b'\x75\x73\x74\x61\x72': ('TAR', 'TAR archive'),
            b'\x53\x51\x4C\x69\x74\x65': ('SQLITE', 'SQLite database'),
            b'\x4E\x45\x53\x1A': ('NES', 'Nintendo Entertainment System ROM'),
            b'\x75\x73\x74\x61\x72\x00\x30\x30': ('TAR', 'TAR archive (UStar)'),
            b'\xCA\xFE\xD0\x0D': ('JAVA', 'Java pack200 file'),
            b'\x4C\x5A\x49\x50': ('LZIP', 'LZIP compressed file'),
            b'\x04\x22\x4D\x18': ('LZ4', 'LZ4 compressed file'),
            b'\x37\x7A\xBC\xAF\x27\x1C': ('7Z', '7-Zip archive'),
            b'\x1F\x9D': ('COMPRESS', 'Compressed file (compress)'),
            b'\x42\x5A\x68': ('BZIP2', 'BZIP2 compressed file'),
            b'\xFD\x37\x7A\x58\x5A\x00': ('XZ', 'XZ compressed file'),
            b'\x04\x22\x4D\x18': ('LZ4', 'LZ4 compressed file'),
            b'\x28\xB5\x2F\xFD': ('ZSTD', 'Zstandard compressed file'),
            b'\x7F\x45\x4C\x46': ('ELF', 'Linux executable'),
            b'\x23\x21': ('SCRIPT', 'Script file'),
            b'\x21\x3C\x61\x72\x63\x68\x3E': ('DEB', 'Debian package'),
            b'\xED\xAB\xEE\xDB': ('RPM', 'RPM package'),
            b'\x5B\x5A\x6f\x6E\x65\x54\x72\x61\x6E\x73\x66\x65\x72\x5D': ('ZONE_IDENTIFIER', 'Windows Zone Identifier'),
            b'\x53\x68\x6F\x63\x6B\x77\x61\x76\x65\x20\x46\x6C\x61\x73\x68': ('SWF', 'Adobe Flash file'),
        }
        
        # Additional signatures for deep scanning
        self.deep_signatures = {
            # Additional specialized signatures for deep scanning
            b'\x00\x01\x00\x00\x00': ('TTF', 'TrueType font file'),
            b'\x4F\x54\x54\x4F': ('OTF', 'OpenType font file'),
            b'\x00\x00\x01\x00': ('ICO', 'Windows icon file'),
            b'\x00\x00\x02\x00': ('CUR', 'Windows cursor file'),
            b'\x49\x49\x2A\x00\x10\x00\x00\x00\x43\x52': ('CR2', 'Canon RAW image format'),
            b'\x38\x42\x50\x53': ('PSD', 'Adobe Photoshop document'),
            b'\x46\x4C\x56\x01': ('FLV', 'Flash video file'),
            b'\x00\x00\x00\x0C\x6A\x50\x20\x20\x0D\x0A\x87\x0A': ('JP2', 'JPEG 2000 image file'),
            b'\x4D\x54\x68\x64': ('MIDI', 'MIDI audio file'),
            b'\x00\x01\x00\x00\x00\x00\x00\x00': ('FONT', 'TrueType Collection font file'),
            b'\x41\x43\x31\x30': ('CAD', 'AutoCAD drawing file'),
            b'\x3C\x21\x64\x6F\x63\x74\x79\x70\x65\x20\x68\x74\x6D\x6C': ('HTML', 'HTML document'),
            b'\x3C\x68\x74\x6D\x6C': ('HTML', 'HTML document'),
            b'\x3C\x48\x54\x4D\x4C': ('HTML', 'HTML document'),
            b'\x3C\x21\x68\x74\x6D\x6C': ('HTML', 'HTML document'),
            b'\x3C\x48\x45\x41\x44': ('HTML', 'HTML document'),
            b'\x3C\x68\x65\x61\x64': ('HTML', 'HTML document'),
            b'\x3C\x62\x6F\x64\x79': ('HTML', 'HTML document'),
            b'\x3C\x42\x4F\x44\x59': ('HTML', 'HTML document'),
            b'\x3C\x73\x63\x72\x69\x70\x74': ('JS', 'JavaScript file'),
            b'\x0A\x0D\x0D\x0A': ('PCAP', 'PCAP capture file'),
            b'\xd4\xc3\xb2\xa1': ('PCAP', 'PCAP capture file'),
            b'\x4D\x53\x43\x46': ('CAB', 'Microsoft cabinet file'),
            b'\x49\x54\x53\x46': ('CHM', 'Microsoft compiled HTML'),
            b'\x3C\x3F\x70\x68\x70': ('PHP', 'PHP script'),
            b'\x23\x20\x54\x68\x69\x73\x20\x69\x73\x20\x61\x20\x73\x68\x65\x6C\x6C\x20\x73\x63\x72\x69\x70\x74': ('SHELL', 'Shell script'),
            b'\x41\x45\x53': ('AES', 'AES encrypted file'),
            b'\x4B\x44\x4D': ('VMDK', 'VMware virtual disk'),
            b'\x2E\x73\x6E\x64': ('AU', 'Sun/NeXT audio file'),
            b'\x10\x00\x00\x00': ('LUAC', 'Lua bytecode'),
            b'\x4C\x75\x61': ('LUA', 'Lua script'),
            b'\x62\x6F\x6F\x6B\x00\x00\x00\x00\x6D\x61\x72\x6B\x00\x00\x00\x00': ('MACHO', 'MacOS X Mach-O binary'),
            b'\x7B\x5C\x72\x74\x66\x31': ('RTF', 'Rich Text Format document'),
            b'\x77\x4F\x46\x46': ('WOFF', 'WOFF font file'),
            b'\x77\x4F\x46\x32': ('WOFF2', 'WOFF2 font file'),
            b'\x1A\x45\xDF\xA3\x93\x42\x82\x88': ('WEBM', 'WebM video file'),
            b'\x30\x26\xB2\x75\x8E\x66\xCF\x11\xA6\xD9\x00\xAA\x00\x62\xCE\x6C': ('ASF', 'Advanced Systems Format'),
            b'\x3C\x3F\x78\x6D\x6C\x20\x76\x65\x72\x73\x69\x6F\x6E\x3D': ('XML', 'XML document'),
        }

    def scan_file(self, data, deep=False):
        """
        Scan file content for known file signatures.
        
        Args:
            data (bytes): Binary content of the file
            deep (bool): Whether to perform deep scan with more signatures
            
        Returns:
            list: List of tuples containing (offset, signature, type, description)
        """
        results = []
        
        # Determine which signature set to use
        signatures = self.signatures.copy()
        if deep:
            signatures.update(self.deep_signatures)
            
        # Search for signatures throughout the file
        for sig, (file_type, description) in signatures.items():
            # Skip empty signatures
            if not sig:
                continue
                
            # Find all occurrences of the signature
            offset = 0
            while True:
                offset = data.find(sig, offset)
                if offset == -1:
                    break
                
                # Add to results
                hex_sig = binascii.hexlify(sig).decode('utf-8').upper()
                results.append((offset, hex_sig, file_type, description))
                offset += 1  # Move past this match to find the next one
                
        # Sort results by offset
        return sorted(results, key=lambda x: x[0])
    
    def run(self):
        """Run the module."""
        super(FileSignatures, self).run()
        
        # Parse arguments
        args = self.parser.parse_args(self.args)
        
        # Validate session
        if not __sessions__.is_set():
            self.log('error', 'No file is currently loaded. Use the "open" command first.')
            return
            
        # Read the file data
        try:
            file_path = __sessions__.current.file.path
            with open(file_path, 'rb') as f:
                data = f.read()
        except Exception as e:
            self.log('error', f'Failed to read file: {e}')
            return
            
        # Default to scan if no specific flag is given
        if not (args.scan or args.deep or args.export):
            args.scan = True
            
        # Scan for signatures
        if args.scan or args.deep:
            self.log('info', f'Scanning file for {"deep " if args.deep else ""}signatures...')
            
            # Perform the scan
            results = self.scan_file(data, deep=args.deep)
            
            # Display results
            if not results:
                self.log('info', 'No file signatures found.')
            else:
                self.log('success', f'Found {len(results)} file signature(s):')
                
                # Prepare table for display
                header = ['Offset', 'Hex Sig', 'File Type', 'Description']
                rows = []
                
                for offset, hex_sig, file_type, description in results:
                    rows.append([
                        str(offset),
                        hex_sig,
                        file_type,
                        description
                    ])
                
                self.log('table', {'header': header, 'rows': rows})
                
        # Export findings to JSON
        if args.export:
            results = self.scan_file(data, deep=True)
            
            if not results:
                self.log('info', 'No file signatures found to export.')
                return
                
            # Convert to JSON-compatible format
            json_data = []
            for offset, hex_sig, file_type, description in results:
                json_data.append({
                    'offset': offset,
                    'signature': hex_sig,
                    'type': file_type,
                    'description': description
                })
                
            # Create output filename
            sample_name = os.path.basename(__sessions__.current.file.path)
            output_path = os.path.join(os.getcwd(), f'{sample_name}_signatures.json')
            
            # Write to file
            try:
                with open(output_path, 'w') as f:
                    json.dump(json_data, f, indent=4)
                self.log('success', f'Exported {len(results)} signatures to {output_path}')
            except Exception as e:
                self.log('error', f'Failed to export results: {e}')
