# Trust-Headers

Trust-Headers is a stateless Streamlit workbench for SOC analysts. It retains only
security-relevant email headers, runs deterministic phishing checks, hashes
attachments without retaining their content, and enriches public indicators
through threat-intelligence APIs.

## Run locally

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
Copy-Item .streamlit\secrets.toml.example .streamlit\secrets.toml
streamlit run app.py
```

API keys are optional for running the app. Missing or rate-limited providers are
labeled in the UI without interrupting other checks.

## Supported inputs

- Pasted raw headers
- `.txt` header files
- `.eml` messages
- `.msg` messages through `extract-msg`

For `.eml` and `.msg` inputs, attachment bytes are used only to calculate their
size and SHA-256 hash. Email bodies and attachment contents are not retained in
the result, cache, logs, or filesystem.

## Threat-intelligence secrets

Put keys in `.streamlit/secrets.toml`; never commit that file:

```toml
ABUSEIPDB_API_KEY = ""
OTX_API_KEY = ""
VIRUSTOTAL_API_KEY = ""
THREATFOX_API_KEY = ""
```

Enrichment is concurrent and bounded by a seven-second total HTTP timeout.
Sanitized results are cached in Streamlit memory for 15 minutes.

## Tests

```powershell
pip install -r requirements-dev.txt
pytest
```
