
import csv
import json
import re
import sys
from typing import Dict, Any, Tuple

REGEX_PATTERNS = {
    "phone": re.compile(r'\b\d{10}\b'),
    "aadhar": re.compile(r'\b\d{12}\b'),
    "passport": re.compile(r'\b[A-Z]{1}[0-9]{7}\b'),
    "upi_id": re.compile(r'\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\b'),
    "email": re.compile(r'\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b'),
    "ip_address": re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b'),
    "name": re.compile(r'\b[A-Z][a-z]+(?:\s[A-Z][a-z]+)+\b')
}

STANDALONE_PII_KEYS = ["phone", "aadhar", "passport", "upi_id"]

COMBINATORIAL_PII_KEYS = ["name", "email", "address", "ip_address", "device_id"]

def redact_phone(phone: str) -> str:
    return f"{phone[:2]}XXXXXX{phone[-2:]}"

def redact_aadhar(aadhar: str) -> str:
    return f"XXXXXXXX{aadhar[-4:]}"

def redact_passport(passport: str) -> str:
    return f"{passport[0]}XXXXX{passport[-2:]}"

def redact_email(email: str) -> str:
    try:
        user, domain = email.split('@')
        return f"{user[0]}{'*' * (len(user) - 2)}{user[-1]}@{domain}"
    except ValueError:
        return "[REDACTED_EMAIL]"

def redact_name(name: str) -> str:
    parts = name.split()
    return " ".join([f"{p[0]}{'*' * (len(p) - 1)}" for p in parts])

def redact_generic(key_name: str) -> str:
    return f"[REDACTED_{key_name.upper()}]"

REDACTION_MAPPING = {
    "phone": redact_phone,
    "aadhar": redact_aadhar,
    "passport": redact_passport,
    "email": redact_email,
    "name": redact_name,
}

def process_record(data: Dict[str, Any]) -> Tuple[Dict[str, Any], bool]:
    is_pii = False
    redacted_data = data.copy()
    pii_keys_to_redact = set()

    for key, value in data.items():
        if key in STANDALONE_PII_KEYS and isinstance(value, str):

            if key in REGEX_PATTERNS and REGEX_PATTERNS[key].fullmatch(value):
                is_pii = True
                pii_keys_to_redact.add(key)


    found_combinatorial_keys = []
    for key in data.keys():
        if key in COMBINATORIAL_PII_KEYS:
            value = data[key]
            if key == "name" and isinstance(value, str) and ' ' not in value:
                continue # Skip single names
            if key == "address" and isinstance(value, str) and len(value.split()) < 3:
                continue
            found_combinatorial_keys.append(key)

    if len(found_combinatorial_keys) >= 2:
        is_pii = True
        for key in found_combinatorial_keys:
            pii_keys_to_redact.add(key)


    if is_pii:
        for key in pii_keys_to_redact:
            if key in redacted_data and redacted_data[key] is not None:
                value_to_redact = str(redacted_data[key])
                redaction_func = REDACTION_MAPPING.get(key)
                if redaction_func:
                    redacted_data[key] = redaction_func(value_to_redact)
                else:
                    redacted_data[key] = redact_generic(key)

    return redacted_data, is_pii
def main(input_file: str, output_file: str):
    try:
        with open(input_file, mode='r', encoding='utf-8') as infile, \
             open(output_file, mode='w', encoding='utf-8', newline='') as outfile:

            reader = csv.DictReader(infile)
            writer = csv.writer(outfile)

            writer.writerow(['record_id', 'redacted_data_json', 'is_pii'])

            print(f"Processing file: {input_file}...")

            for row in reader:
                record_id = row.get('record_id', '')
                data_json_str = row.get('data_json', '{}')
                try:
                    data_dict = json.loads(data_json_str)
                except json.JSONDecodeError:
                    print(f"Warning: Could not decode JSON for record_id {record_id}. Skipping.")
                    continue

                redacted_data, is_pii = process_record(data_dict)


                redacted_json_str = json.dumps(redacted_data)

                writer.writerow([record_id, redacted_json_str, is_pii])

            print(f"Processing complete. Output written to {output_file}")

    except FileNotFoundError:
        print(f"Error: The file '{input_file}' was not found.")
        sys.exit(1)
    except Exception as e:
        print(f"An unexpected error occurred: {e}")
        sys.exit(1)

if __name__ == "__main__":
    input_csv_file = "iscp_pii_dataset_-_Sheet1.csv"
    output_csv_file = "redacted_output.csv"
    main(input_csv_file, output_csv_file)
