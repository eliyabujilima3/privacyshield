# PrivacyShield

A web-based data anonymization prototype built with Flask, Pandas, and Bootstrap-style
vanilla CSS. Upload a CSV/Excel dataset of citizen records, review auto-detected
sensitive columns, anonymize them (masking/hashing-style redaction), and download
the protected file.

## Features

- Upload CSV or Excel files (up to 20 MB)
- Automatic detection of likely PII columns: Name, National ID, Phone, Email,
  Address, Date of Birth
- Live dataset preview (first 10 rows) before anonymizing
- Per-column control over which anonymization method to apply
- Before/after comparison on the results page
- Download the protected dataset as CSV or Excel
- Simple JSON-based activity log (`logs/activity_log.json`) recording each
  anonymization job — a lightweight stand-in for the optional `activity_logs` table

## Setup

```bash
cd privacyshield
python3 -m venv venv
source venv/bin/activate          # Windows: venv\Scripts\activate
pip install -r requirements.txt
python app.py
```

The app runs at **http://localhost:5000**.

A ready-to-use sample dataset is included at `test_data/citizens.csv` if you want
to try the flow immediately.

## How it works

1. **Home** — drag and drop or browse for a `.csv` / `.xlsx` file.
2. **Preview & Select** — PrivacyShield scans column headers, pre-checks columns
   it thinks are sensitive, and shows the first 10 records. You can check/uncheck
   columns and change the masking method per column (Name, Phone, Email,
   National ID, Address, Date of Birth, or Generic Text).
3. **Protect** — click "Anonymize dataset." The server masks the selected columns
   and writes a new file to `outputs/`.
4. **Download** — review a before/after comparison and download the protected
   file as CSV or Excel.

## Masking rules (Module 4)

| Field | Example input | Example output |
|---|---|---|
| Name | `John Michael` | `J*** M*******` |
| Phone | `0712345678` | `071*****78` |
| Email | `john@gmail.com` | `j***@gmail.com` |
| National ID | `199912345678` | `********5678` |
| Address | `Dar es Salaam` | `Region Hidden` |
| Date of Birth | `1999-05-12` | `1999-**-**` |
| Generic | any other selected column | first character kept, rest masked |

These are simple, reversible-looking but non-reversible redactions suited for a
prototype. A production system would likely add configurable hashing (e.g. HMAC
with a secret key) for fields that need consistent pseudonyms across exports.

## Project structure

```
privacyshield/
├── app.py                 # Flask routes and app wiring
├── anonymizer.py           # Detection rules + masking functions
├── requirements.txt
├── uploads/                 # Raw uploaded files (gitignored in practice)
├── outputs/                 # Anonymized files ready for download
├── logs/                    # app.log + activity_log.json
├── templates/
│   ├── base.html
│   ├── index.html            # Home / upload
│   ├── preview.html           # Column selection + data preview
│   ├── result.html            # Before/after + download
│   └── error.html
├── static/
│   ├── css/style.css
│   ├── js/app.js
│   └── images/
└── test_data/
    └── citizens.csv
```

## Notes / next steps

- **Administrator role** (view logs, view reports, manage users) is scoped as a
  future feature per the brief and is not implemented in this prototype.
- **Database**: an optional `activity_logs` table is described in the brief;
  this prototype uses a JSON file (`logs/activity_log.json`) instead to avoid
  requiring a database for a prototype. Swapping in SQLite later is
  straightforward — the `log_activity()` function in `app.py` is the only
  place that would need to change.
- Uploaded/anonymized files are stored on disk per session (`uploads/`,
  `outputs/`); for a real deployment you'd want a cleanup job or short-lived
  storage (e.g. S3 with expiry) rather than keeping files indefinitely.
