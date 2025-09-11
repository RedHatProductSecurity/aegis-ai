#!/usr/bin/env bash

uv run uvicorn aegis_ai_web.src.main:app --port 9000 --loop uvloop --http httptools --host 0.0.0.0