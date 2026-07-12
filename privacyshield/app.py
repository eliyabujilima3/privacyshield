"""
PrivacyShield - Data Anonymization System
Flask application entry point.
"""

import os
import json
import uuid
import logging
from datetime import datetime, timezone

import pandas as pd
from flask import (
    Flask, render_template, request, redirect,
    url_for, send_file, flash, abort
)
from werkzeug.utils import secure_filename

from anonymizer import (
    detect_sensitive_columns,
    anonymize_dataframe,
    TYPE_LABELS,
    MASK_FUNCTIONS,
)

# --------------------------------------------------------------------------
# App configuration
# --------------------------------------------------------------------------
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
UPLOAD_FOLDER = os.path.join(BASE_DIR, "uploads")
OUTPUT_FOLDER = os.path.join(BASE_DIR, "outputs")
LOG_FOLDER = os.path.join(BASE_DIR, "logs")
ACTIVITY_LOG_FILE = os.path.join(LOG_FOLDER, "activity_log.json")

ALLOWED_EXTENSIONS = {"csv", "xlsx", "xls"}
MAX_CONTENT_LENGTH = 20 * 1024 * 1024  # 20 MB, per spec

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "privacyshield-dev-secret-key")
app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER
app.config["OUTPUT_FOLDER"] = OUTPUT_FOLDER
app.config["MAX_CONTENT_LENGTH"] = MAX_CONTENT_LENGTH

for folder in (UPLOAD_FOLDER, OUTPUT_FOLDER, LOG_FOLDER):
    os.makedirs(folder, exist_ok=True)

# --------------------------------------------------------------------------
# Logging (app-level, to console + file)
# --------------------------------------------------------------------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler(os.path.join(LOG_FOLDER, "app.log")),
    ],
)
logger = logging.getLogger("privacyshield")


# --------------------------------------------------------------------------
# In-memory session registry
# --------------------------------------------------------------------------
# Maps a short-lived file_id -> metadata about that upload/anonymization job.
# Kept simple (dict) since this is a prototype; a real deployment would use
# a database or Flask server-side sessions.
JOBS = {}


def allowed_file(filename: str) -> bool:
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS


def read_dataset(filepath: str) -> pd.DataFrame:
    """Read a CSV or Excel file into a DataFrame."""
    ext = filepath.rsplit(".", 1)[1].lower()
    if ext == "csv":
        return pd.read_csv(filepath)
    return pd.read_excel(filepath)


def write_dataset(df: pd.DataFrame, filepath: str):
    """Write a DataFrame to CSV or Excel based on the file extension."""
    ext = filepath.rsplit(".", 1)[1].lower()
    if ext == "csv":
        df.to_csv(filepath, index=False)
    else:
        df.to_excel(filepath, index=False, engine="openpyxl")


def log_activity(entry: dict):
    """Append an activity record to the JSON activity log (optional feature)."""
    entry["timestamp"] = datetime.now(timezone.utc).isoformat()
    records = []
    if os.path.exists(ACTIVITY_LOG_FILE):
        try:
            with open(ACTIVITY_LOG_FILE, "r") as f:
                records = json.load(f)
        except (json.JSONDecodeError, IOError):
            records = []
    records.append(entry)
    with open(ACTIVITY_LOG_FILE, "w") as f:
        json.dump(records, f, indent=2)
    logger.info("Activity logged: %s", entry)


def get_job_or_404(file_id: str) -> dict:
    job = JOBS.get(file_id)
    if not job:
        abort(404, description="This session has expired or does not exist. Please upload your file again.")
    return job


# --------------------------------------------------------------------------
# Routes
# --------------------------------------------------------------------------
@app.route("/")
def home():
    return render_template("index.html")


@app.route("/upload", methods=["POST"])
def upload():
    if "dataset" not in request.files:
        flash("No file was selected. Please choose a CSV or Excel file.", "error")
        return redirect(url_for("home"))

    file = request.files["dataset"]

    if file.filename == "":
        flash("No file was selected. Please choose a CSV or Excel file.", "error")
        return redirect(url_for("home"))

    if not allowed_file(file.filename):
        flash("Unsupported file format. Please upload a .csv or .xlsx file.", "error")
        return redirect(url_for("home"))

    original_name = secure_filename(file.filename)
    file_id = uuid.uuid4().hex[:12]
    ext = original_name.rsplit(".", 1)[1].lower()
    stored_name = f"{file_id}_original.{ext}"
    filepath = os.path.join(app.config["UPLOAD_FOLDER"], stored_name)

    try:
        file.save(filepath)
        df = read_dataset(filepath)
    except Exception as exc:
        logger.exception("Failed to read uploaded file")
        flash(f"We couldn't read that file: {exc}", "error")
        if os.path.exists(filepath):
            os.remove(filepath)
        return redirect(url_for("home"))

    if df.empty or len(df.columns) == 0:
        flash("The uploaded file appears to be empty.", "error")
        os.remove(filepath)
        return redirect(url_for("home"))

    JOBS[file_id] = {
        "original_name": original_name,
        "filepath": filepath,
        "ext": ext,
        "num_rows": len(df),
        "num_cols": len(df.columns),
        "columns": list(df.columns),
    }

    logger.info("Uploaded file %s -> job %s (%d rows, %d cols)",
                original_name, file_id, len(df), len(df.columns))

    return redirect(url_for("preview", file_id=file_id))


@app.route("/preview/<file_id>")
def preview(file_id):
    job = get_job_or_404(file_id)
    df = read_dataset(job["filepath"])

    detected = detect_sensitive_columns(df)

    preview_rows = df.head(10).fillna("").astype(str).values.tolist()
    columns = list(df.columns)

    # Build per-column info for the template: is it flagged sensitive,
    # and what PII type was guessed (or 'generic' as a fallback choice).
    column_info = []
    for col in columns:
        pii_type = detected.get(col, "generic")
        column_info.append({
            "name": col,
            "is_sensitive": col in detected,
            "suggested_type": pii_type,
            "suggested_label": TYPE_LABELS.get(pii_type, "Generic Text"),
        })

    return render_template(
        "preview.html",
        file_id=file_id,
        original_name=job["original_name"],
        num_rows=job["num_rows"],
        num_cols=job["num_cols"],
        columns=columns,
        column_info=column_info,
        preview_rows=preview_rows,
        type_labels=TYPE_LABELS,
        mask_types=list(MASK_FUNCTIONS.keys()),
    )


@app.route("/anonymize/<file_id>", methods=["POST"])
def anonymize(file_id):
    job = get_job_or_404(file_id)
    df = read_dataset(job["filepath"])

    selected_columns = request.form.getlist("selected_columns")

    if not selected_columns:
        flash("Please select at least one column to anonymize.", "error")
        return redirect(url_for("preview", file_id=file_id))

    columns_config = {}
    for col in selected_columns:
        # Each selected column has an accompanying <select> named "type__<col>"
        pii_type = request.form.get(f"type__{col}", "generic")
        columns_config[col] = pii_type

    try:
        anonymized_df = anonymize_dataframe(df, columns_config)
    except Exception as exc:
        logger.exception("Anonymization failed for job %s", file_id)
        flash(f"Something went wrong while anonymizing the data: {exc}", "error")
        return redirect(url_for("preview", file_id=file_id))

    output_name = f"{file_id}_anonymized.{job['ext']}"
    output_path = os.path.join(app.config["OUTPUT_FOLDER"], output_name)
    write_dataset(anonymized_df, output_path)

    job["output_path"] = output_path
    job["anonymized_columns"] = columns_config
    job["before_preview"] = df.head(5).fillna("").astype(str).values.tolist()
    job["after_preview"] = anonymized_df.head(5).fillna("").astype(str).values.tolist()

    log_activity({
        "file_id": file_id,
        "filename": job["original_name"],
        "anonymized_columns": list(columns_config.keys()),
        "records_processed": len(df),
    })

    return redirect(url_for("result", file_id=file_id))


@app.route("/result/<file_id>")
def result(file_id):
    job = get_job_or_404(file_id)
    if "output_path" not in job:
        flash("Please anonymize your dataset first.", "error")
        return redirect(url_for("preview", file_id=file_id))

    anonymized_labels = [
        {"column": col, "label": TYPE_LABELS.get(t, "Generic Text")}
        for col, t in job["anonymized_columns"].items()
    ]

    return render_template(
        "result.html",
        file_id=file_id,
        original_name=job["original_name"],
        num_rows=job["num_rows"],
        num_cols=job["num_cols"],
        anonymized_labels=anonymized_labels,
        columns=job["columns"],
        before_preview=job["before_preview"],
        after_preview=job["after_preview"],
        ext=job["ext"],
    )


@app.route("/download/<file_id>/<fmt>")
def download(file_id, fmt):
    job = get_job_or_404(file_id)
    if "output_path" not in job:
        abort(404, description="No anonymized file is available yet.")

    if fmt not in ("csv", "xlsx"):
        abort(400, description="Unsupported download format.")

    base_name = job["original_name"].rsplit(".", 1)[0]
    download_name = f"{base_name}_anonymized.{fmt}"

    # If the requested format matches what's already on disk, send it directly.
    if fmt == job["ext"] or (fmt == "xlsx" and job["ext"] == "xls"):
        return send_file(job["output_path"], as_attachment=True, download_name=download_name)

    # Otherwise convert on the fly (e.g. uploaded CSV, user wants Excel download).
    df = read_dataset(job["output_path"])
    tmp_path = os.path.join(app.config["OUTPUT_FOLDER"], f"{file_id}_anonymized_converted.{fmt}")
    write_dataset(df, tmp_path)
    return send_file(tmp_path, as_attachment=True, download_name=download_name)


# --------------------------------------------------------------------------
# Error handlers
# --------------------------------------------------------------------------
@app.errorhandler(404)
def not_found(e):
    return render_template("error.html", code=404, message=str(e.description)), 404


@app.errorhandler(413)
def too_large(e):
    return render_template("error.html", code=413,
                            message="That file is too large. Maximum upload size is 20 MB."), 413


@app.errorhandler(500)
def server_error(e):
    logger.exception("Internal server error")
    return render_template("error.html", code=500,
                            message="Something went wrong on our end. Please try again."), 500


if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=5000)
