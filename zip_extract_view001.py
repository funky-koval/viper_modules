import os
import zipfile
import gzip
import bz2
import tarfile
from django.views import View
from django.http import HttpResponse
from django.views.decorators.csrf import csrf_exempt
from django.utils.decorators import method_decorator
from core.sample import add_file
from core.database import open_db
from .views import upload_temp  # or adjust the import if needed


@method_decorator(csrf_exempt, name='dispatch')
class ZipExtractView(View):
    def post(self, request, project, sha256):
        compression = request.POST.get('compression')
        zip_pass = request.POST.get('zip_pass', '')
        tags = request.POST.get('tag_list', '')
        mime = request.POST.get('app')
        file_hash = request.POST.get('file_hash')
        file_name = request.POST.get('file_name')

        open_db(project)

        # Point to Viper's storage path
        sample_path = f"/opt/viper/storage/{project}/{file_hash[:2]}/{file_hash}"

        added = []
        skipped = []
        errors = []

        with upload_temp() as temp_dir:
            try:
                if compression == 'zip':
                    with zipfile.ZipFile(sample_path, 'r') as zf:
                        zf.extractall(path=temp_dir, pwd=zip_pass.encode() if zip_pass else None)
                        file_paths = [os.path.join(root, f) for root, _, files in os.walk(temp_dir) for f in files]

                elif compression == 'gz':
                    out_path = os.path.join(temp_dir, file_name[:-3])
                    with gzip.open(sample_path, 'rb') as f_in, open(out_path, 'wb') as f_out:
                        f_out.write(f_in.read())
                    file_paths = [out_path]

                elif compression == 'bz2':
                    out_path = os.path.join(temp_dir, file_name[:-4])
                    with bz2.open(sample_path, 'rb') as f_in, open(out_path, 'wb') as f_out:
                        f_out.write(f_in.read())
                    file_paths = [out_path]

                elif compression == 'tar':
                    with tarfile.open(sample_path, 'r:*') as tf:
                        tf.extractall(temp_dir)
                        file_paths = [os.path.join(root, f) for root, _, files in os.walk(temp_dir) for f in files]

                else:
                    return HttpResponse("<pre>Unsupported compression type.</pre>")

            except Exception as e:
                return HttpResponse(f"<pre>Error extracting archive: {str(e)}</pre>")

            for fpath in file_paths:
                try:
                    result = add_file(fpath, name=os.path.basename(fpath), tags=tags, parent=file_hash)
                    if result:
                        added.append((os.path.basename(fpath), result))
                    else:
                        skipped.append(os.path.basename(fpath))
                except Exception as e:
                    errors.append(f"{os.path.basename(fpath)}: {str(e)}")

        # Build result HTML
        html = "<pre><strong>Zip Extract Results</strong>\n\n"

        if added:
            html += "Added to Viper:\n"
            for name, sha in added:
                html += f"  ✔ {name} → {sha}\n"
            html += "\n"

        if skipped:
            html += "Already existed:\n"
            for name in skipped:
                html += f"  ⚠ {name}\n"
            html += "\n"

        if errors:
            html += "Errors:\n"
            for err in errors:
                html += f"  ❌ {err}\n"
            html += "\n"

        html += "</pre>"

        return HttpResponse(html)
