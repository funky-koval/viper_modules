@method_decorator(csrf_exempt, name='dispatch')
class ZipExtractView(View):
    def post(self, request, project, sha256):
        compression = request.POST.get('compression')
        zip_pass = request.POST.get('zip_pass', '')
        tags = request.POST.get('tag_list', '')
        mime = request.POST.get('app')
        file_hash = request.POST.get('file_hash')
        file_name = request.POST.get('file_name')

        # For now just return debug info
        html = f"""
        <pre>
        Received:
        Compression: {compression}
        Password: {zip_pass or '(none)'}
        Tags: {tags}
        File Hash: {file_hash}
        File Name: {file_name}
        MIME: {mime}
        </pre>
        """
        return HttpResponse(html)
