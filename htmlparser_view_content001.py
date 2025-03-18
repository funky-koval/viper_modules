import os
import time
import cv2
import base64
import shutil
import tempfile
import pytesseract
from selenium import webdriver
from selenium.webdriver.firefox.options import Options
from PIL import Image
from viper.core.database import Database

def view_content(self, url, hash256):
    # Variables
    end_url = None
    url_img = ''
    temp_folder = tempfile.gettempdir()
    img_folder = os.path.join(temp_folder, 'viper_url_extracts')

    if not url.startswith("http"):
        self.log("error", "Not a valid URL, missing http prefix, will pre-append it to the supplied string")
        url = "http://" + url

    # Confirm the dump path
    if not os.path.exists(img_folder):
        try:
            os.makedirs(img_folder)
        except Exception as e:
            self.log("error", f"Unable to create directory at {img_folder}: {e}")
            return None, None

    img_file = os.path.join(img_folder, 'my_screenshot.png')
    grey_img_file = os.path.join(img_folder, 'grey.png')
    result = ''

    try:
        # Set browser variables and get screenshot
        options = Options()
        options.headless = True
        driver = webdriver.Firefox(options=options)
        driver.set_window_size(1366, 768)
        driver.get(url)
        time.sleep(20)
        end_url = driver.current_url
        driver.save_screenshot(img_file)
        driver.quit()

        # Tesseract config
        config = ('-l eng --oem 1 --psm 6')

        # Load, enlarge, and convert the image to grayscale
        img = cv2.imread(img_file)
        img = cv2.resize(img, None, fx=3, fy=3, interpolation=cv2.INTER_CUBIC)
        img = cv2.bilateralFilter(img, 9, 75, 75)
        gray = cv2.cvtColor(img, cv2.COLOR_BGR2GRAY)
        cv2.imwrite(grey_img_file, gray)

        # Carve with Tesseract OCR
        try:
            result = pytesseract.image_to_string(Image.open(grey_img_file), config=config)
            if result:
                note_title = "OCR Results"
                db = Database()
                rows = db.find('sha256', hash256)

                if rows:
                    row = rows[0]
                    if not any(n.title == "OCR Results" for n in row.note):
                        db.add_note(hash256, note_title, result)
        except Exception as e:
            self.log("error", f"OCR processing failed: {e}")

        # Embed image in base64 format
        with open(img_file, "rb") as image_file:
            encoded_string = base64.b64encode(image_file.read()).decode('utf-8')
            url_img = f'<div><img alt="Embedded Image" src="data:image/png;base64,{encoded_string}"/></div>'

        if url_img:
            self.log('info', f'<pre>{url_img}</pre>')
        else:
            self.log('error', "Not implemented yet")

        # Cleanup temp folder
        if os.path.exists(img_folder):
            shutil.rmtree(img_folder)

    except Exception as e:
        result = f"OCR failed due to: {e}"

    return result, end_url
