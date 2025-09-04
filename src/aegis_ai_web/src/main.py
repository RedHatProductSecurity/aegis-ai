"""
aegis web


"""

import logging
import os
from enum import Enum
from pathlib import Path
from typing import Dict, Type, Annotated

import logfire
import yaml
from fastapi import FastAPI, Request, HTTPException, Form
from fastapi.responses import HTMLResponse, JSONResponse, FileResponse, Response
from starlette.middleware.base import BaseHTTPMiddleware

from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from aegis_ai import config_logging
from aegis_ai.agents import public_feature_agent, rh_feature_agent

from aegis_ai.data_models import CVEID, cveid_validator
from aegis_ai.features import cve, component
from aegis_ai.features.data_models import AegisAnswer

from . import AEGIS_REST_API_VERSION, feature_agent


class HSTSHeaderMiddleware(BaseHTTPMiddleware):
    """middleware to add HSTS header to HTTP responses"""

    async def dispatch(self, request: Request, call_next):
        response = await call_next(request)
        response.headers["Strict-Transport-Security"] = (
            "max-age=31536000; includeSubDomains"
        )
        return response


config_logging()

app = FastAPI(
    title="Aegis REST-API",
    description="A simple web console and REST API for Aegis.",
    version=AEGIS_REST_API_VERSION,
)

# middleware to add HSTS header to HTTP responses (it is safe to send the HSTS
# header over plain-text HTTP because the header shall be ignored by the client
# unless it is received over HTTPS)
app.add_middleware(HSTSHeaderMiddleware)

logfire.instrument_fastapi(app)

BASE_DIR = Path(__file__).parent
TEMPLATES_DIR = BASE_DIR / "templates"
STATIC_DIR = BASE_DIR / "static"

# Setup  for serving HTML
templates = Jinja2Templates(directory=TEMPLATES_DIR)

# Mount static files
app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")

favicon_path = os.path.join(STATIC_DIR, "favicon.ico")

if "public" in feature_agent:
    llm_agent = public_feature_agent
else:
    llm_agent = rh_feature_agent


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


@app.post("/console")
async def generate_response(
    request: Request,
    user_instruction: Annotated[str, Form()],
    goals: Annotated[str, Form()],
    rules: Annotated[str, Form()],
):
    """
    Handles the submission of a prompt, simulates an LLM response,
    and re-renders the console with the results.
    """

    try:
        llm_response = await llm_agent.run(user_instruction, output_type=AegisAnswer)
        response = llm_response.output
        return templates.TemplateResponse(
            "console.html",
            {
                "request": request,
                "user_instruction": user_instruction,
                "goals": goals,
                "rules": rules,
                "confidence": response.confidence,
                "completeness": response.completeness,
                "consistency": response.consistency,
                "tools_used": response.tools_used,
                "explanation": response.explanation,
                "answer": response.answer,
                "raw_output": llm_response.all_messages(),
            },
        )

    except Exception as e:
        raise HTTPException(500, detail=f"Error executing general query': {e}")


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
        feature_instance = FeatureClass(agent=llm_agent)
        result = await feature_instance.exec(validated_input)
        if detail:
            return result
        return result.output
    except Exception as e:
        raise HTTPException(500, detail=f"Error executing CVE feature '{feature}': {e}")


@app.post(
    f"/api/{AEGIS_REST_API_VERSION}/analysis/cve/{{feature}}",
    response_class=JSONResponse,
)
async def cve_analysis_with_body(
    feature: CVEFeatureName, cve_data: Request, detail: bool = False
):
    cve_data = await cve_data.json()
    cve_id = cve_data["cve_id"]

    if feature.value not in cve_feature_registry:
        raise HTTPException(404, detail=f"CVE feature '{feature.value}' not found.")
    FeatureClass = cve_feature_registry[feature.value]
    try:
        validated_input = cve_data
    except Exception as e:
        raise HTTPException(
            422, detail=f"Invalid input for CVE feature '{feature}': {e}"
        )
    try:
        feature_instance = FeatureClass(agent=llm_agent)
        result = await feature_instance.exec(cve_id, static_context=validated_input)
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
        feature_instance = FeatureClass(agent=llm_agent)
        result = await feature_instance.exec(validated_input)
        if detail:
            return result
        return result.output
    except Exception as e:
        raise HTTPException(
            500, detail=f"Error executing Component feature '{feature}': {e}"
        )
