"""
aegis web


"""

import logging
import os
from enum import Enum
from pathlib import Path
from typing import Dict, Type, Annotated, cast, Any

import yaml
from fastapi import FastAPI, Request, HTTPException, Form, Query
from fastapi.responses import HTMLResponse, JSONResponse, FileResponse, Response

from starlette.middleware.base import BaseHTTPMiddleware
from fastapi.middleware.cors import CORSMiddleware

from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from aegis_ai import config_logging, get_settings
from aegis_ai.agents import public_feature_agent, rh_feature_agent

from aegis_ai.data_models import CVEID, cveid_validator
from aegis_ai.features import cve, component
from aegis_ai.features.data_models import AegisAnswer

from . import (
    AEGIS_REST_API_VERSION,
    web_feature_agent,
    ENABLE_CONSOLE,
)
from .data_models import Feedback, FeatureKPI
from .endpoints.kpi import get_cve_kpi, SortOrder
from .feedback_logger import AegisLogger


class HSTSHeaderMiddleware(BaseHTTPMiddleware):
    """middleware to add HSTS header to HTTP responses"""

    async def dispatch(self, request: Request, call_next):
        response = await call_next(request)
        response.headers["Strict-Transport-Security"] = (
            "max-age=31536000; includeSubDomains"
        )
        return response


config_logging()

app: FastAPI = FastAPI(
    title="Aegis REST-API",
    description="A simple web console and REST API for Aegis.",
    version=AEGIS_REST_API_VERSION,
)

# middleware to add HSTS header to HTTP responses (it is safe to send the HSTS
# header over plain-text HTTP because the header shall be ignored by the client
# unless it is received over HTTPS)
app.add_middleware(cast(Any, HSTSHeaderMiddleware))

# optionally enable Kerberos authentication
kerberos_spn = os.getenv("AEGIS_WEB_SPN")
if kerberos_spn:
    # do not depend on `fastapi-gssapi` unless it is actually needed
    from fastapi_gssapi import GSSAPIMiddleware
    from starlette.responses import Response

    class CustomGSSAPIMiddleware(GSSAPIMiddleware):
        """middleware to add GSSAPI authentication for all paths except /healthz"""

        async def __call__(self, scope, receive, send):
            if scope["type"] == "http" and scope["path"] == "/healthz":
                # skip authentication and return HTTP 204 with no content
                resp = Response(status_code=204)
                return await resp(scope, receive, send)

            # route any other traffic to GSSAPIMiddleware
            return await super().__call__(scope, receive, send)

    # add middleware for GSSAPI authentication to the app
    app.add_middleware(cast(Any, CustomGSSAPIMiddleware), spn=kerberos_spn)

# middleware enabling CORS
cors_target_regex = os.getenv("AEGIS_CORS_TARGET_REGEX", "http(s)?://localhost(:5173)?")
app.add_middleware(
    cast(Any, CORSMiddleware),
    allow_methods=["*"],
    allow_headers=["*"],
    allow_credentials=True,
    allow_origin_regex=cors_target_regex,
)

BASE_DIR = Path(__file__).parent
TEMPLATES_DIR = BASE_DIR / "templates"
STATIC_DIR = BASE_DIR / "static"

# Setup  for serving HTML
templates = Jinja2Templates(directory=TEMPLATES_DIR)

# Mount static files
app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")

favicon_path = os.path.join(STATIC_DIR, "favicon.ico")

if "public" in web_feature_agent:
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
    return templates.TemplateResponse(
        request, "index.html", {"version": get_settings().app_version}
    )


if ENABLE_CONSOLE:

    @app.get("/console", response_class=HTMLResponse)
    async def console(request: Request):
        return templates.TemplateResponse(
            request, "console.html", {"version": get_settings().app_version}
        )

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
            llm_response = await llm_agent.run(
                user_instruction, output_type=AegisAnswer
            )
            response = llm_response.output
            return templates.TemplateResponse(
                request,
                "console.html",
                {
                    "user_instruction": user_instruction,
                    "goals": goals,
                    "rules": rules,
                    "confidence": response.confidence,
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
    "suggest-description": cve.SuggestDescriptionText,
    "suggest-statement": cve.SuggestStatementText,
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


@app.get(
    f"/api/{AEGIS_REST_API_VERSION}/analysis/kpi/cve",
    summary="Get CVE Analysis KPI Metrics",
    description="Retrieve Key Performance Indicator (KPI) metrics for CVE analysis feedback, filtered by feature name. Returns a dictionary mapping feature names to their KPI responses (acceptance score percentage and all matching log entries sorted by datetime). Use feature='all' to get KPIs for all features. For single feature queries, the dict contains one key-value pair.",
    response_model=Dict[str, FeatureKPI],
    responses={
        200: {
            "description": "Successful response with KPI metrics",
            "content": {
                "application/json": {
                    "examples": {
                        "single_feature": {
                            "summary": "Response for single feature query",
                            "value": {
                                "suggest-impact": {
                                    "acceptance_percentage": 75.0,
                                    "entries": [
                                        {
                                            "datetime": "2025-01-15 10:30:45.123",
                                            "accepted": True,
                                            "aegis_version": "1.0.0",
                                        },
                                        {
                                            "datetime": "2025-01-15 11:00:00.456",
                                            "accepted": True,
                                            "aegis_version": "1.0.0",
                                        },
                                        {
                                            "datetime": "2025-01-15 11:30:15.789",
                                            "accepted": False,
                                            "aegis_version": "1.0.0",
                                        },
                                        {
                                            "datetime": "2025-01-15 12:00:30.012",
                                            "accepted": True,
                                            "aegis_version": "1.0.0",
                                        },
                                    ],
                                },
                            },
                        },
                        "all_features": {
                            "summary": "Response when feature='all'",
                            "value": {
                                "suggest-impact": {
                                    "acceptance_percentage": 75.0,
                                    "entries": [],
                                },
                                "suggest-cwe": {
                                    "acceptance_percentage": 50.0,
                                    "entries": [],
                                },
                            },
                        },
                        "empty_response": {
                            "summary": "Response when no entries exist for feature",
                            "value": {
                                "suggest-impact": {
                                    "acceptance_percentage": 0.0,
                                    "entries": [],
                                },
                            },
                        },
                    },
                }
            },
        },
        422: {
            "description": "Validation error - invalid order parameter or missing feature",
            "content": {
                "application/json": {
                    "example": {
                        "detail": [
                            {
                                "type": "missing",
                                "loc": ["query", "feature"],
                                "msg": "Field required",
                            }
                        ]
                    }
                }
            },
        },
        500: {
            "description": "Internal server error",
            "content": {
                "application/json": {
                    "example": {
                        "detail": "Error retrieving KPI data for feature 'suggest-impact': <error message>"
                    }
                }
            },
        },
    },
)
async def cve_kpi(
    feature: str = Query(
        ...,
        description="Feature name to filter entries by. Valid values include: 'suggest-impact', 'suggest-cwe', 'suggest-description', 'suggest-statement', 'identify-pii', 'cvss-diff-explainer', or 'all' to get KPIs for all features.",
        examples=["suggest-impact", "suggest-cwe", "suggest-description", "all"],
    ),
    order: SortOrder = Query(
        default=SortOrder.ASC,
        description="Sort order for datetime field. Must be 'asc' (ascending, oldest first) or 'desc' (descending, newest first). Defaults to 'asc'.",
        examples=["asc", "desc"],
    ),
) -> Dict[str, FeatureKPI]:
    """
    Get KPI metrics for CVE analysis feedback filtered by feature.

    This endpoint calculates the acceptance rate (percentage of entries where accept=True)
    for a specific feature and returns all matching log entries sorted by datetime.

    **Parameters:**
    - **feature**: Required. The feature name to filter by (e.g., 'suggest-impact', 'suggest-cwe', or 'all' for all features)
    - **order**: Optional. Sort order for entries by datetime ('asc' or 'desc'). Defaults to 'asc'.

    **Returns:**
    - Dict[str, FeatureKPI] mapping feature names to their KPI responses.
      For a single feature query, the dict contains one key-value pair.
      For feature='all', the dict contains all features.

    **Example:**
    ```
    GET /api/v1/analysis/kpi/cve?feature=suggest-impact&order=desc
    GET /api/v1/analysis/kpi/cve?feature=all
    ```
    """
    result = get_cve_kpi(feature, order)
    # Always return Dict[str, FeatureKPI] for consistent API structure
    # FastAPI will automatically serialize using response_model
    return result


@app.post("/api/v1/feedback")
async def save_feedback(feedback: Feedback):
    """
    Receive feedback and log it to CSV file.

    All data is preserved without modification. CSV library handles escaping.
    """
    try:
        # Normalize accept to lowercase for consistency
        accept_str = str(feedback.accept).lower()
        row_data = {
            "feature": feedback.feature,
            "cve_id": feedback.cve_id or "",
            "email": feedback.email or "",
            "actual": feedback.actual or "",
            "expected": feedback.expected or "",
            "request_time": feedback.request_time or "",
            "accept": accept_str,
            "rejection_comment": feedback.rejection_comment or "",
        }

        # Write to CSV file (automatic escaping)
        AegisLogger.write(row_data)

        logging.info(
            f"Feedback logged: feature={feedback.feature}, cve_id={feedback.cve_id}"
        )
        return {"status": "Feedback received and logged successfully."}

    except Exception as e:
        entry = f"{feedback.cve_id}/{feedback.feature}"
        logging.warning(
            f"Failed to process feedback for {entry}: {e.__class__.__name__}"
        )
        logging.debug(
            f"Error details for feedback submission {entry}: {e}", exc_info=True
        )
        raise HTTPException(
            status_code=500,
            detail="An internal error occurred while processing feedback.",
        )
