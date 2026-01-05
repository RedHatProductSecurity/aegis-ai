#!/bin/bash -x

# trigger download of MITRE CWE data (and build of the TF-IDF index, which is instant anyway)
uv run aegis suggest-cwe CVE-2025-23395

# run the web service
uv run uvicorn aegis_ai_web.src.main:app --port 9000 --loop uvloop --http httptools --host 0.0.0.0
