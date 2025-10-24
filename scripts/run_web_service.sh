#!/bin/bash -x

# trigger build of the FAISS index
AEGIS_LLM_TIMEOUT_SECS=900 uv run aegis suggest-cwe CVE-2025-23395

# run the web service
uv run uvicorn aegis_ai_web.src.main:app --port 9000 --loop uvloop --http httptools --host 0.0.0.0
