import os
import requests
import tempfile
import hashlib
from zipfile import ZipFile

from django.contrib.auth.mixins import LoginRequiredMixin
from django.views.generic import TemplateView
from django.shortcuts import redirect
from django.urls import reverse
from django.contrib import messages

from core.config import VMRAY_URL, VMRAY_API_KEY, VMRAY_URL_SAMPLE
from core.database import open_db
from core.sample import add_file


class VMRayDownloadView(LoginRequiredMixin, TemplateView):
    """Download a sample from VMRay and store extracted files"""

    def post(self, request, *args, **kwargs):
        project = request.POST.get('project', 'default')
        open_db(project)

        vmray_id = request.POST.get('vmray_id')
        tags = request.POST.get('tag_list', '')

        if not vmray_id:
            messages.error(request, "No VMRay ID provided.")
            return redirect(reverse("main-page-project", kwargs={"project": project}))

        tags = f"vmray,{tags}" if tags else "vmray"

        # Build VMRay URL
        headers = {"Authorization": f"api_key {VMRAY_API_KEY}"}
        download_url = f"{VMRAY_URL}{VMRAY_URL_SAMPLE}".format(vmray_id)

        try:
            response = requests.get(download_url, headers=headers, verify=False)
        except Exception as e:
            messages.error(request, f"Failed contacting VMRay: {e}")
            return redirect(reverse("main-page-project", kwargs={"project": project}))

        if response.status_code != 200:
            messages.error(request, f"VMRay download failed: HTTP {response.status_code}")
            return redirect(reverse("main-page-project", kwargs={"project": project}))

        # Save the zip file to temp
        with tempfile.NamedTemporaryFile(delete=False) as tmp_zip:
            tmp_zip.write(response.content)
            tmp_zip.flush()
            zip_path = tmp_zip.name

        extracted_files = []
        temp_dir = tempfile.mkdtemp()

        try:
            with ZipFile(zip_path) as zf:
                zf.extractall(temp_dir, pwd=b'infected')
                for root, _, files in os.walk(temp_dir):
                    for f in files:
                        extracted_files.append(os.path.join(root, f))
        except Exception as e:
            messages.error(request, f"Error extracting VMRay ZIP: {e}")
            return redirect(reverse("main-page-project", kwargs={"project": project}))

        if not extracted_files:
            messages.error(request, "No files found in the VMRay archive.")
            return redirect(reverse("main-page-project", kwargs={"project": project}))

        stored_any = False
        for file_path in extracted_files:
            sha256 = add_file(file_path, tags=tags)
            if sha256:
                stored_any = True
                messages.success(request, f"Stored file from VMRay archive: {sha256}")
            else:
                messages.warning(request, f"File already exists: {os.path.basename(file_path)}")

        if stored_any:
            return redirect(reverse("main-page-project", kwargs={"project": project}))
        else:
            messages.warning(request, "All extracted files already exist in the project.")
            return redirect(reverse("main-page-project", kwargs={"project": project}))
