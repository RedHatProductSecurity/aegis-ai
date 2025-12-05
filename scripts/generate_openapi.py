#!/usr/bin/env python3
"""
Generate OpenAPI documentation from FastAPI app.

This script generates the OpenAPI specification from the FastAPI application
and saves it to docs/openapi.json and docs/openapi.yml.
"""

import json
import sys
from pathlib import Path

import yaml

# Add the src directory to the path so we can import the app
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from aegis_ai_web.src.main import app


def generate_openapi():
    """Generate OpenAPI documentation and save to files."""
    # Get the OpenAPI schema from FastAPI
    openapi_schema = app.openapi()

    # Get the docs directory
    docs_dir = Path(__file__).parent.parent / "docs"
    docs_dir.mkdir(exist_ok=True)

    # Save as JSON
    json_path = docs_dir / "openapi.json"
    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(openapi_schema, f, indent=2, ensure_ascii=False)
    print(f"✓ Generated {json_path}")

    # Save as YAML
    yaml_path = docs_dir / "openapi.yml"
    with open(yaml_path, "w", encoding="utf-8") as f:
        yaml.dump(openapi_schema, f, default_flow_style=False, sort_keys=False, allow_unicode=True)
    print(f"✓ Generated {yaml_path}")


if __name__ == "__main__":
    generate_openapi()

