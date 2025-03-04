import os
import json
import shutil

def process_results(result_dir, file_sha):
    """ Parses the output of BoxJS and extracts relevant analysis data """
    results_folder = os.path.join(result_dir, f"{file_sha}-results")

    if not os.path.exists(results_folder):
        self.log('warning', "No results found in analysis.")
        return []

    output_data = {}

    # List all JSON files in the results directory
    for filename in os.listdir(results_folder):
        if filename.endswith(".json"):
            file_path = os.path.join(results_folder, filename)
            try:
                with open(file_path, "r", encoding="utf-8") as fd:
                    data = json.load(fd)  # Load the JSON data
                    output_data[filename] = data  # Store it for logging
            except Exception as e:
                self.log('error', f"Error reading {filename}: {e}")

    # Remove temporary results folder
    shutil.rmtree(result_dir)

    # Log all output files
    if output_data:
        self.log('info', "Extracted BoxJS Analysis Results:")
        for filename, data in output_data.items():
            self.log('info', f"{filename}:")
            self.log('info', json.dumps(data, indent=4))  # Pretty print JSON data
    else:
        self.log('warning', "No relevant data extracted from the JavaScript file.")

    return output_data
