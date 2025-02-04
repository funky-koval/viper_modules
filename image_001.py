# -*- coding: utf-8 -*-
# This file is part of Viper - https://github.com/viper-framework/viper
# See the file 'LICENSE' for copying permission.

from io import BytesIO
import logging
import os
import tempfile
import base64
import cv2
import pytesseract
from PIL import Image as Im

from viper.common.abstracts import Module
from viper.core.session import __sessions__
from viper.core.database import Database

log = logging.getLogger('viper')

class Image(Module):
    cmd = 'image'
    description = 'Perform analysis on images'
    authors = ['nex']

    def __init__(self):
        super(Image, self).__init__()
        self.parser.add_argument('-g', '--ghiro', action='store_true', help='Upload the file to imageforensic.org and retrieve report')
        self.parser.add_argument('-o', '--ocr', action='store_true', help='Run OCR on image file')

    def ghiro(self):
        try:
            import requests
        except ImportError:
            self.log('error', "Missing dependency, install requests (`pip install requests`)")
            return

        payload = dict(private='true', json='true')
        files = dict(image=BytesIO(__sessions__.current.file.data))

        response = requests.post('http://www.imageforensic.org/api/submit/', data=payload, files=files)
        results = response.json()

        if results['success']:
            report = results['report']
            if len(report['signatures']) > 0:
                self.log('', "Signatures:")
                for signature in report['signatures']:
                    self.log('item', signature['description'])
            for k, v in report.items():
                if k == 'signatures':
                    continue
                if isinstance(v, dict):
                    for k1, v1 in v.items():
                        self.log('info', '{}: {}'.format(k1, v1))
                else:
                    self.log('info', '{}: {}'.format(k, v))
        else:
            self.log('error', "The analysis failed")

    def ocr(self, img_file, hash256):
        result = ''
        temp_folder = tempfile.gettempdir()
        img_folder = os.path.join(temp_folder, 'viper_url_extracts')
        # Confirm the dump path
        if not os.path.exists(img_folder):
            try:
                os.makedirs(img_folder)
            except Exception as e:
                self.log('error', "Unable to create directory at {0}: {1}".format(img_folder, e))
                return None

        # Image file details
        grey_img_file = os.path.join(img_folder, 'grey.png')
        try:
            # Tesseract config
            config = ('-l eng --oem 1 --psm 6')
            # Load the image, enlarge and convert it to grayscale
            image = cv2.imread(img_file)
            img = cv2.resize(image, None, fx=3, fy=3, interpolation=cv2.INTER_CUBIC)
            gray = cv2.bilateralFilter(img, 9, 75, 75)
            gray = cv2.cvtColor(gray, cv2.COLOR_BGR2GRAY)
            cv2.imwrite(grey_img_file, gray)

            # Carve with Tesseract OCR
            try:
                result = pytesseract.image_to_string(Im.open(grey_img_file), config=config)
                if result:
                    note_title = "OCR Results"
                    db = Database()
                    rows = db.find("sha256", hash256)
                    row_sha256 = [row for row in rows if row.note and row.note != note_title]
                    if rows:
                        row = rows[0]
                        if not [n for n in row.note if 'OCR Results' == n.title]:
                            db.add_note(hash256, note_title, result)
            except Exception as e:
                result = "OCR Failed due to: {}".format(e)

            with open(img_file, "rb") as image_file:
                encoded_string = base64.b64encode(image_file.read())
                url_img = '<div><img alt="Embedded Image" src="data:image/png;base64,' + encoded_string.decode() + '"/></div>'
                if url_img:
                    self.log('info', "<pre>{}</pre>".format(url_img))
        except Exception as e:
            result = "OCR Failed due to: {}".format(e)

        return result

    def run(self):
        super(Image, self).run()
        if self.args is None:
            return

        if not __sessions__.is_set():
            self.log('error', "No open session. This command expects a file to be open.")
            return

        if self.args.ghiro:
            self.ghiro()
        elif self.args.ocr:
            try:
                path = __sessions__.current.file.path
                hash256 = __sessions__.current.file.sha256
            except Exception as e:
                self.log('error', "Something went wrong: {0}".format(e))
                return
            data = self.ocr(path, hash256)
            if data:
                self.log('info', "<pre>{0}</pre>".format(data))
        else:
            self.log('error', 'At least one of the parameters is required')
            self.usage()
