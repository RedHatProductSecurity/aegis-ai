"""
aegis web


"""

import logging
import os
from enum import Enum
from pathlib import Path
from typing import Dict, Type

import logfire
import yaml
from fastapi import FastAPI, Request, HTTPException
from fastapi.responses import HTMLResponse, JSONResponse, FileResponse, Response

from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from aegis_ai import config_logging

# rh_feature_agent can be substituted with public_feature_agent
from aegis_ai.agents import rh_feature_agent as feature_agent

from aegis_ai.data_models import CVEID, cveid_validator
from aegis_ai.features import cve, component
from . import AEGIS_REST_API_VERSION

config_logging()

app = FastAPI(
    title="Aegis REST-API",
    description="A simple web console and REST API for Aegis.",
    version=AEGIS_REST_API_VERSION,
)

logfire.instrument_fastapi(app)

BASE_DIR = Path(__file__).parent
TEMPLATES_DIR = BASE_DIR / "templates"
STATIC_DIR = BASE_DIR / "static"

# Setup  for serving HTML
templates = Jinja2Templates(directory=TEMPLATES_DIR)

# Mount static files
app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")

favicon_path = os.path.join(STATIC_DIR, "favicon.ico")


@app.get("/favicon.ico", include_in_schema=False)
async def favicon():
    return FileResponse(favicon_path)


@app.get("/openapi.yml", include_in_schema=False)
async def get_openapi_yaml() -> Response:
    """
    Return OpenAPI specification in YAML format.
    """
    openapi_schema = app.openapi()
    yaml_schema = yaml.dump(openapi_schema)
    return Response(content=yaml_schema, media_type="application/vnd.oai.openapi")


@app.get("/", response_class=HTMLResponse)
async def home(request: Request):
    return templates.TemplateResponse("index.html", {"request": request})


@app.get("/console", response_class=HTMLResponse)
async def console(request: Request):
    return templates.TemplateResponse("console.html", {"request": request})


@app.post("/generate_response")
async def generate_response(request: Request):
    """
    Handles the submission of a prompt, simulates an LLM response,
    and re-renders the console with the results.
    """
    user_prompt = request.form().__dict__.get("user_prompt")

    # --- Simulate LLM Response ---
    # In a real application, you would make an API call to an LLM here.
    # For this simple example, we'll just echo the prompt and add a prefix.
    if user_prompt:
        llm_response = f"Simulated LLM Response: You asked '{user_prompt}'. This is a placeholder response."
    else:
        llm_response = "Please enter a prompt."

    # Render the template again, passing the user's prompt and the simulated response
    return templates.TemplateResponse(
        "console.html",
        {"request": request, "user_prompt": user_prompt, "llm_response": llm_response},
    )


cve_feature_registry: Dict[str, Type] = {
    "suggest-impact": cve.SuggestImpact,
    "suggest-cwe": cve.SuggestCWE,
    "rewrite-description": cve.RewriteDescriptionText,
    "rewrite-statement": cve.RewriteStatementText,
    "identify-pii": cve.IdentifyPII,
    "cvss-diff-explainer": cve.CVSSDiffExplainer,
}
CVEFeatureName = Enum(
    "ComponentFeatureName",
    {name: name for name in cve_feature_registry.keys()},
    type=str,
)


@app.get(
    f"/api/{AEGIS_REST_API_VERSION}/analysis/cve",
    response_class=JSONResponse,
)
async def cve_analysis(feature: CVEFeatureName, cve_id: CVEID, detail: bool = False):
    if feature not in cve_feature_registry:
        raise HTTPException(404, detail=f"CVE feature '{feature}' not found.")

    FeatureClass = cve_feature_registry[feature]

    try:
        validated_input = cveid_validator.validate_python(cve_id)
    except Exception as e:
        raise HTTPException(
            422, detail=f"Invalid input for CVE feature '{feature}': {e}"
        )

    try:
        feature_instance = FeatureClass(agent=feature_agent)
        result = await feature_instance.exec(validated_input)
        if detail:
            return result
        return result.output
    except Exception as e:
        raise HTTPException(500, detail=f"Error executing CVE feature '{feature}': {e}")


component_feature_registry: Dict[str, Type] = {
    "component-intelligence": component.ComponentIntelligence,
}
ComponentFeatureName = Enum(
    "ComponentFeatureName",
    {name: name for name in component_feature_registry.keys()},
    type=str,
)


@app.get(
    f"/api/{AEGIS_REST_API_VERSION}/analysis/component",
    response_class=JSONResponse,
)
async def component_analysis(
    feature: ComponentFeatureName, component_name: str, detail: bool = False
):
    logging.info(feature)
    if feature not in component_feature_registry:
        raise HTTPException(404, detail=f"Component feature '{feature}' not found.")

    FeatureClass = component_feature_registry[feature]

    try:
        validated_input = component_name
    except Exception as e:
        raise HTTPException(
            422, detail=f"Invalid input for Component feature '{feature}': {e}"
        )

    try:
        feature_instance = FeatureClass(agent=feature_agent)
        result = await feature_instance.exec(validated_input)
        if detail:
            return result
        return result.output
    except Exception as e:
        raise HTTPException(
            500, detail=f"Error executing Component feature '{feature}': {e}"
        )
