class UrlDownloadView(LoginRequiredMixin, TemplateView):
    """Store a URL as a sample file"""

    def post(self, request, *args, **kwargs):
        project = request.POST.get('project', 'default')
        open_db(project)

        url = request.POST.get('url')
        tags = request.POST.get('tag_list', '')

        if not url:
            messages.error(request, "No URL provided")
            return redirect(reverse("main-page-project", kwargs={"project": project}))

        tags = f"url,{tags}"  # Ensure 'url' is always added as a tag

        # Convert the URL into a valid filename
        safe_filename = url.replace("://", "_").replace("/", "_") + ".txt"

        # Define the sample storage path
        sample_dir = os.path.join(cfg.storage.path, project)
        os.makedirs(sample_dir, exist_ok=True)

        # Save the URL as a text file
        file_path = os.path.join(sample_dir, safe_filename)
        with open(file_path, "w") as file:
            file.write(url)

        # Register the URL file as a sample in Viper’s database
        sha_256 = add_file(file_path, name=safe_filename, tags=tags)

        if sha_256:
            messages.success(request, f"Stored URL as {safe_filename}")
            return redirect(reverse('main-page-project', kwargs={'project': project}))
        else:
            messages.error(request, "Unable to Store The File, already in database")
            return redirect(reverse("main-page-project", kwargs={"project": project}))
