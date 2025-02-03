import os
import tempfile
import pytesseract
from pdf2image import convert_from_path
from PIL import Image

def pdf_ocr_extract(self, pdf_file):
    object_counter = 1
    grey_object_counter = 1
    result = ''

    # Create temporary directories for extracted images
    temp_folder = tempfile.gettempdir()
    img_folder = os.path.join(temp_folder, 'viper_pdf_extracts')
    grey_img_folder = os.path.join(temp_folder, 'grey_viper_pdf_extracts')

    # Create directories if they don't exist
    for folder in [img_folder, grey_img_folder]:
        if not os.path.exists(folder):
            try:
                os.makedirs(folder)
            except Exception as e:
                self.log('error', f"Unable to create directory at {folder}: {e}")
                return result

    try:
        # Convert PDF pages to images
        images = convert_from_path(pdf_file, dpi=200)
        for page_num, img in enumerate(images, start=1):
            # Save full-color image
            out_img = os.path.join(img_folder, f"{object_counter}_pdf_page_{page_num}.jpg")
            img.save(out_img, "JPEG", quality=100)
            object_counter += 1

            # Convert image to greyscale for better OCR accuracy
            grey_out_img = os.path.join(grey_img_folder, f"{grey_object_counter}_grey_pdf_page_{page_num}.jpg")
            img = img.convert("L")  # Convert to greyscale
            img.save(grey_out_img, "JPEG", quality=100)
            grey_object_counter += 1

            # Perform OCR on the greyscale image
            text = pytesseract.image_to_string(Image.open(grey_out_img), lang='eng')
            result += text + '\n'

    except Exception as e:
        self.log('error', f"An error occurred during PDF OCR extraction: {e}")
        return result

    # Clean up temporary directories
    for folder in [img_folder, grey_img_folder]:
        try:
            shutil.rmtree(folder)
        except Exception as e:
            self.log('error', f"Failed to clean up temporary folder {folder}: {e}")

    return result
