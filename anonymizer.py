"""
anonymizer.py
PrivacyShield anonymization engine.

Handles:
  - Detecting likely sensitive (PII) columns from a DataFrame's headers
  - Masking values based on the detected/assigned data type
"""

import re
import pandas as pd

# --------------------------------------------------------------------------
# Sensitive column detection
# --------------------------------------------------------------------------
# Keyword -> PII type. Matching is done against a "cleaned" version of the
# column header (lowercased, punctuation/underscores stripped).
DETECTION_RULES = [
    ("name", ["name", "fullname", "fname", "lname", "surname", "firstname", "lastname"]),
    ("nida", ["nida", "nationalid", "idnumber", "id", "ssn", "passport"]),
    ("phone", ["phone", "mobile", "tel", "telephone", "contact"]),
    ("email", ["email", "mail"]),
    ("address", ["address", "location", "residence", "street", "region", "ward", "district"]),
    ("dob", ["dob", "dateofbirth", "birthdate", "birthday"]),
]

# Human-friendly labels for the UI
TYPE_LABELS = {
    "name": "Name",
    "nida": "National ID",
    "phone": "Phone Number",
    "email": "Email Address",
    "address": "Address",
    "dob": "Date of Birth",
    "generic": "Generic Text",
}


def _clean_header(col_name: str) -> str:
    """Lowercase and strip non-alphanumeric characters from a column name."""
    return re.sub(r"[^a-z0-9]", "", str(col_name).lower())


def detect_sensitive_columns(df: pd.DataFrame):
    """
    Inspect DataFrame column headers and guess which ones are sensitive.

    Returns a dict: { column_name: pii_type }
    Only columns that matched a rule are included. Columns not matched
    are left out (the user can still manually select them in the UI,
    where they'll be treated as 'generic').
    """
    detected = {}
    for col in df.columns:
        cleaned = _clean_header(col)
        for pii_type, keywords in DETECTION_RULES:
            if any(keyword in cleaned for keyword in keywords):
                detected[col] = pii_type
                break
    return detected


# --------------------------------------------------------------------------
# Value-level masking functions
# --------------------------------------------------------------------------
def _mask_all_but_first(word: str) -> str:
    """'Michael' -> 'M******'"""
    word = str(word)
    if len(word) <= 1:
        return word
    return word[0] + "*" * (len(word) - 1)


def mask_name(value) -> str:
    """'John Michael' -> 'J*** M*******' (each word masked individually)."""
    if pd.isna(value) or str(value).strip() == "":
        return value
    words = str(value).split()
    return " ".join(_mask_all_but_first(w) for w in words)


def mask_phone(value) -> str:
    """'0712345678' -> '071*****78' (keep first 3 and last 2 digits)."""
    if pd.isna(value) or str(value).strip() == "":
        return value
    s = str(value).strip()
    digits_only = re.sub(r"\D", "", s)
    if len(digits_only) <= 5:
        return "*" * len(s)
    visible_start = digits_only[:3]
    visible_end = digits_only[-2:]
    masked_middle = "*" * (len(digits_only) - 5)
    return f"{visible_start}{masked_middle}{visible_end}"


def mask_email(value) -> str:
    """'john@gmail.com' -> 'j***@gmail.com'"""
    if pd.isna(value) or str(value).strip() == "":
        return value
    s = str(value).strip()
    if "@" not in s:
        return _mask_all_but_first(s)
    local, domain = s.split("@", 1)
    if len(local) <= 1:
        masked_local = local
    else:
        masked_local = local[0] + "*" * (len(local) - 1)
    return f"{masked_local}@{domain}"


def mask_nida(value) -> str:
    """'199912345678' -> '********5678' (keep last 4 digits only)."""
    if pd.isna(value) or str(value).strip() == "":
        return value
    s = str(value).strip()
    digits_only = re.sub(r"\D", "", s)
    if len(digits_only) <= 4:
        return "*" * len(s)
    visible_end = digits_only[-4:]
    masked_start = "*" * (len(digits_only) - 4)
    return f"{masked_start}{visible_end}"


def mask_address(value) -> str:
    """Any address value -> 'Region Hidden' (full generalization)."""
    if pd.isna(value) or str(value).strip() == "":
        return value
    return "Region Hidden"


def mask_dob(value) -> str:
    """'1999-05-12' -> '1999-**-**' (keep only the birth year)."""
    if pd.isna(value) or str(value).strip() == "":
        return value
    s = str(value).strip()
    match = re.match(r"^(\d{4})[-/]\d{1,2}[-/]\d{1,2}", s)
    if match:
        return f"{match.group(1)}-**-**"
    # Fallback: try to find any 4-digit year in the string
    year_match = re.search(r"\d{4}", s)
    if year_match:
        return f"{year_match.group(0)}-**-**"
    return "*" * len(s)


def mask_generic(value) -> str:
    """Fallback masking: keep first character, mask the rest."""
    if pd.isna(value) or str(value).strip() == "":
        return value
    return _mask_all_but_first(str(value))


MASK_FUNCTIONS = {
    "name": mask_name,
    "phone": mask_phone,
    "email": mask_email,
    "nida": mask_nida,
    "address": mask_address,
    "dob": mask_dob,
    "generic": mask_generic,
}


def anonymize_dataframe(df: pd.DataFrame, columns_config: dict):
    """
    Apply anonymization to the given DataFrame.

    columns_config: { column_name: pii_type }
        pii_type must be one of the keys in MASK_FUNCTIONS.

    Returns a NEW anonymized DataFrame (original is left untouched).
    """
    anonymized = df.copy()
    for col, pii_type in columns_config.items():
        if col not in anonymized.columns:
            continue
        mask_fn = MASK_FUNCTIONS.get(pii_type, mask_generic)
        anonymized[col] = anonymized[col].apply(mask_fn)
    return anonymized
