import os
import hashlib
import json
import time
import requests
import yara
import magic
from flask import Flask, render_template, request, redirect, url_for, flash
from werkzeug.utils import secure_filename

# ------------------------------
# CONFIGURATION
# ------------------------------
app = Flask(__name__)
app.secret_key = "malware-detector-123"

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
UPLOAD_FOLDER = os.path.join(BASE_DIR, "uploads")
YARA_RULES_FOLDER = os.path.join(BASE_DIR, "yara_rules")

os.makedirs(UPLOAD_FOLDER, exist_ok=True)
os.makedirs(YARA_RULES_FOLDER, exist_ok=True)

app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER

# INSERT YOUR API KEY HERE
VT_API_KEY = "4d7c70a1d23cc30728a719c63f5062469c1f5ebfda5870ad9a325be9aab01654"  # Replace with your VirusTotal API Key


# ------------------------------
# UTILITY FUNCTIONS
# ------------------------------

def calculate_sha256(file_path):
    """Generate SHA256 hash for the uploaded file."""
    sha256_hash = hashlib.sha256()
    with open(file_path, "rb") as f:
        for byte_block in iter(lambda: f.read(4096), b""):
            sha256_hash.update(byte_block)
    return sha256_hash.hexdigest()


def get_file_info(file_path):
    """Extract metadata: file type, size, hash."""
    file_size = os.path.getsize(file_path)
    file_type = magic.from_file(file_path, mime=True)
    file_hash = calculate_sha256(file_path)
    return {
        "file_type": file_type,
        "size": file_size,
        "sha256": file_hash
    }


# ------------------------------
# LEVEL-WISE YARA SCANNING
# ------------------------------
def scan_with_yara_levelwise(file_path):
    """Scan uploaded file with level-wise YARA rules."""
    levels = ["easy", "medium", "hard"]
    results = {"easy": [], "medium": [], "hard": []}

    try:
        for level in levels:
            level_folder = os.path.join(YARA_RULES_FOLDER, level)

            if not os.path.exists(level_folder):
                continue

            rule_files = [
                os.path.join(level_folder, f)
                for f in os.listdir(level_folder)
                if f.endswith(".yar")
            ]

            if not rule_files:
                continue

            # Compile rules for this specific level
            rules = yara.compile(filepaths={str(i): rf for i, rf in enumerate(rule_files)})

            matches = rules.match(file_path)
            results[level] = [str(match) for match in matches]

    except Exception as e:
        print(f"YARA scanning error: {e}")

    return results


# ------------------------------
# VIRUSTOTAL SCANNING
# ------------------------------
def scan_with_virustotal(file_path):
    if VT_API_KEY == "YOUR_API_KEY_HERE":
        return {"warning": "VirusTotal API Key missing in app.py"}

    url = "https://www.virustotal.com/api/v3/files"
    headers = {"x-apikey": VT_API_KEY}

    try:
        with open(file_path, "rb") as f:
            files = {"file": (os.path.basename(file_path), f)}
            response = requests.post(url, headers=headers, files=files)

        if response.status_code in (200, 202):
            analysis_id = response.json()["data"]["id"]

            time.sleep(5)  # wait for analysis
            report_url = f"https://www.virustotal.com/api/v3/analyses/{analysis_id}"
            report = requests.get(report_url, headers=headers)

            if report.status_code == 200:
                data = report.json()
                stats = data["data"]["attributes"]["stats"]
                results = data["data"]["attributes"].get("results", {})

                engine_results = {
                    engine: details.get("result")
                    for engine, details in results.items()
                }

                return {
                    "engines": engine_results,
                    "stats": stats
                }

            return {"error": "Could not fetch VirusTotal report."}

        return {"error": f"VirusTotal upload failed: {response.text}"}

    except Exception as e:
        return {"error": f"VirusTotal Error: {str(e)}"}


# ------------------------------
# ROUTES
# ------------------------------
@app.route("/")
def index():
    return render_template("index.html")


@app.route("/scan", methods=["POST"])
def scan_file():
    if "file" not in request.files:
        flash("No file uploaded.")
        return redirect(url_for("index"))

    file = request.files["file"]

    if file.filename == "":
        flash("No file selected.")
        return redirect(url_for("index"))

    filename = secure_filename(file.filename)
    file_path = os.path.join(app.config["UPLOAD_FOLDER"], filename)
    file.save(file_path)
    time.sleep(0.5)

    # File Info
    file_info = get_file_info(file_path)

    # YARA level-wise scan
    yara_results = scan_with_yara_levelwise(file_path)

    # VirusTotal Scan
    vt_results = scan_with_virustotal(file_path)
    vt_results["meta"] = file_info

    return render_template(
        "result.html",
        filename=filename,
        yara_results=yara_results,
        vt_results=vt_results
    )


if __name__ == "__main__":
    app.run(debug=True)
