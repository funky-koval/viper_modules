def run_boxjs(self, file_path, file_sha):
    """ Executes BoxJS on the JavaScript file """
    self.log('info', f"[DEBUG] Running BoxJS on: {file_path}")
    self.log('info', f"[DEBUG] File SHA: {file_sha}")

    if not file_path or not isinstance(file_path, (str, bytes, os.PathLike)):
        self.log('error', f"[ERROR] Invalid file_path: {file_path}")
        return None

    box_js_result_dir = tempfile.mkdtemp()
    node_binary = shutil.which("node")

    if not node_binary:
        self.log('error', "Node.js is not installed or not found in PATH.")
        return None

    boxjs_script = os.path.join(cfg.modules.path, "box-js-master", "run.js")

    if not os.path.exists(boxjs_script):
        self.log('error', "BoxJS script not found. Ensure box-js-master is installed in modules directory.")
        return None

    cmd_line = f"{node_binary} {boxjs_script} --output-dir {box_js_result_dir} {file_path}"
    self.log('info', f"[DEBUG] Executing: {cmd_line}")

    try:
        subprocess.run(cmd_line, shell=True, check=True)
    except subprocess.CalledProcessError as e:
        self.log('error', f"BoxJS execution failed: {e}")
        return None

    return box_js_result_dir, file_sha
