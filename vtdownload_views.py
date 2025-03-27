import requests
from tempfile import NamedTemporaryFile

from django.contrib.auth.mixins import LoginRequiredMixin
from django.views.generic import TemplateView
from django.shortcuts import redirect
from django.urls import reverse
from django.contrib import messages

from core.database import open_db
from viper.core.storage import store_sample
from core.config import VT_API_KEY, VIRUSTOTAL_URL_DOWNLOAD


class VtDownloadView(LoginRequiredMixin, TemplateView):
    """Download a sample from VirusTotal and store it as a local sample"""

    def post(self, request, *args, **kwargs):
        project = request.POST.get('project', 'default')
        open_db(project)

        vt_hash = request.POST.get('vt_hash')
        tags = request.POST.get('tag_list', '')

        if not vt_hash:
            messages.error(request, "No VirusTotal hash provided.")
            return redirect(reverse("main-page-project", kwargs={"project": project}))

        # Prepare API request
        params = {'apikey': VT_API_KEY, 'hash': vt_hash}
        try:
            response = requests.get(VIRUSTOTAL_URL_DOWNLOAD, params=params)
        except Exception as e:
            messages.error(request, f"VirusTotal request failed: {e}")
            return redirect(reverse("main-page-project", kwargs={"project": project}))

        if response.status_code != 200:
            messages.error(request, f"Failed to download file from VirusTotal (HTTP {response.status_code})")
            return redirect(reverse("main-page-project", kwargs={"project": project}))

        # Save to temporary file
        with NamedTemporaryFile(delete=False) as tmp:
            tmp.write(response.content)
            tmp.flush()
            tmp_path = tmp.name

        # Store it using core.storage
        full_tags = f"virustotal,{tags}" if tags else "virustotal"
        sha256 = store_sample(tmp_path, tags=full_tags)

        if sha256:
            messages.success(request, f"Downloaded and stored sample from VirusTotal: {sha256}")
            return redirect(reverse("main-page-project", kwargs={"project": project}))
        else:
            messages.error(request, "Failed to store downloaded sample.")
            return redirect(reverse("main-page-project", kwargs={"project": project}))
