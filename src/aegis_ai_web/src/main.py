"""
aegis web


"""

import asyncio
import json
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
from .data_models import Feedback, ProgrammaticFeedback, FeatureKPI
from .endpoints.kpi import get_cve_kpi, SortOrder
from .feedback_logger import feedback_logger, programmatic_feedback_logger
from .semantic_scoring import (
    calculate_semantic_proximity_score,
)


def log_exception_safely(e: Exception, context: str) -> None:
    """Log exception with warning (no traceback) and debug (with traceback), then raise HTTPException."""
    logging.warning(f"{context}: {e.__class__.__name__}")
    logging.debug(f"Error details for {context}: {e}", exc_info=True)


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


@app.exception_handler(json.JSONDecodeError)
async def json_decode_exception_handler(request: Request, exc: json.JSONDecodeError):
    """Handle JSON decode errors from invalid request bodies."""
    logging.warning(
        f"Invalid JSON in request body: {exc.msg} at line {exc.lineno} column {exc.colno}"
    )
    return JSONResponse(
        status_code=400,
        content={"detail": f"Invalid JSON in request body: {exc.msg}"},
    )


@app.exception_handler(UnicodeDecodeError)
async def unicode_decode_exception_handler(request: Request, exc: UnicodeDecodeError):
    """Handle Unicode decode errors from invalid request body encoding."""
    logging.warning(
        f"Invalid UTF-8 encoding in request body: {exc.reason} at position {exc.start}"
    )
    return JSONResponse(
        status_code=400,
        content={"detail": "Invalid UTF-8 encoding in request body"},
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
            log_exception_safely(e, "Error executing general query")
            raise HTTPException(
                status_code=500,
                detail="An internal error occurred while executing the query.",
            )


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
        msg = f"Invalid input for CVE feature '{feature}'"
        log_exception_safely(e, msg)
        raise HTTPException(status_code=422, detail=msg)

    try:
        feature_instance = FeatureClass(agent=llm_agent)
        result = await feature_instance.exec(validated_input)
        if detail:
            return result
        return result.output
    except Exception as e:
        log_exception_safely(e, f"Error executing CVE feature '{feature}'")
        raise HTTPException(
            status_code=500,
            detail=f"An internal error occurred while executing CVE feature '{feature}'.",
        )


@app.post(
    f"/api/{AEGIS_REST_API_VERSION}/analysis/cve/{{feature}}",
    response_class=JSONResponse,
)
async def cve_analysis_with_body(
    feature: CVEFeatureName, cve_data: Request, detail: bool = False
):
    try:
        cve_data = await cve_data.json()
        cve_id = cve_data["cve_id"]
    except KeyError as e:
        log_exception_safely(e, "Missing required field: 'cve_id'")
        raise HTTPException(status_code=400, detail="Missing required field: 'cve_id'")

    if feature.value not in cve_feature_registry:
        raise HTTPException(404, detail=f"CVE feature '{feature.value}' not found.")
    FeatureClass = cve_feature_registry[feature.value]
    try:
        validated_input = cve_data
    except Exception as e:
        msg = f"Invalid input for CVE feature '{feature}'"
        log_exception_safely(e, msg)
        raise HTTPException(status_code=422, detail=msg)
    try:
        feature_instance = FeatureClass(agent=llm_agent)
        result = await feature_instance.exec(cve_id, static_context=validated_input)
        if detail:
            return result
        return result.output
    except Exception as e:
        log_exception_safely(e, f"Error executing CVE feature '{feature}'")
        raise HTTPException(
            status_code=500,
            detail=f"An internal error occurred while executing CVE feature '{feature}'.",
        )


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
        msg = f"Invalid input for Component feature '{feature}'"
        log_exception_safely(e, msg)
        raise HTTPException(status_code=422, detail=msg)

    try:
        feature_instance = FeatureClass(agent=llm_agent)
        result = await feature_instance.exec(validated_input)
        if detail:
            return result
        return result.output
    except Exception as e:
        log_exception_safely(e, f"Error executing Component feature '{feature}'")
        raise HTTPException(
            status_code=500,
            detail=f"An internal error occurred while executing Component feature '{feature}'.",
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
            "cve_id": feedback.cve_id
            or feedback.cveId
            or "",  # FIXME: an interim compatibility fix for OSIM
            "email": feedback.email or "",
            "actual": feedback.actual or "",
            "expected": feedback.expected or "",
            "request_time": feedback.request_time or "",
            "accept": accept_str,
            "rejection_comment": feedback.rejection_comment or "",
        }

        # Write to CSV file (automatic escaping)
        feedback_logger.write(row_data)

        logging.info(
            f"Feedback logged: feature={feedback.feature}, cve_id={feedback.cve_id}"
        )
        return {"status": "Feedback received and logged successfully."}

    except Exception as e:
        entry = f"{feedback.cve_id}/{feedback.feature}"
        log_exception_safely(e, f"Failed to process feedback for {entry}")
        raise HTTPException(
            status_code=500,
            detail="An internal error occurred while processing feedback.",
        )


def calculate_acceptance_score(suggested: str, submitted: str) -> float | None:
    """
    Calculate acceptance score based on suggested and submitted values.

    Args:
        suggested: The AI-suggested value
        submitted: The value actually submitted by the user

    Returns:
        1.0 if values match exactly, None otherwise
    """
    if not suggested or not submitted:
        return None
    if suggested == submitted:
        return 1.0
    return None


async def process_semantic_scoring(
    feature: str,
    suggested: str,
    submitted: str,
    cve_id: str,
    entry_datetime: str,
    email: str,
) -> float | None:
    """
    Process semantic scoring for a feature asynchronously.

    This method attempts to calculate semantic proximity score for features that
    support it. If semantic scoring fails or times out, the entry remains with an
    empty acceptance_score and can be retried later via retry_failed_scoring.py.
    This method is designed to be run as a background task and should not block
    the main feedback submission flow.

    Args:
        feature: The feature name
        suggested: The AI-suggested value
        submitted: The value actually submitted by the user
        cve_id: The CVE ID
        entry_datetime: The datetime string for the entry
        email: The user's email

    Returns:
        The semantic score if available, None otherwise
    """

    try:
        semantic_score, explanation = await calculate_semantic_proximity_score(
            suggested=suggested,
            submitted=submitted,
            feature=feature,
            cve_id=cve_id,
        )

        if semantic_score is not None:
            # Use semantic score if available - update the CSV entry
            updates = {"acceptance_score": str(semantic_score)}
            if explanation:
                updates["llmjudge_explanation"] = explanation
            programmatic_feedback_logger.update_entry(
                datetime_str=entry_datetime,
                cve_id=cve_id,
                feature=feature,
                updates=updates,
            )
            logging.debug(
                f"Using semantic proximity score {semantic_score} for "
                f"feature={feature}, cve_id={cve_id}"
            )
            return semantic_score
        else:
            # Semantic scoring failed - entry will remain with empty score
            # and can be retried later via retry_failed_scoring.py
            logging.warning(
                f"Semantic scoring returned no score for feature={feature}, "
                f"cve_id={cve_id}, entry has empty acceptance_score "
                f"(can be retried via retry_failed_scoring.py)"
            )
            return None

    except Exception as e:
        # Log error but don't fail the feedback submission
        # Entry will remain with empty score and can be retried later
        logging.warning(
            f"Error during semantic scoring for feature={feature}, "
            f"cve_id={cve_id}: {e.__class__.__name__}: {str(e)}"
        )
        return None


@app.post("/api/v1/programmatic-feedback")
async def save_programmatic_feedback(feedback: ProgrammaticFeedback):
    """
    Receive programmatic feedback and log it to CSV file.

    This endpoint captures AI suggestion acceptance data when users save flaws,
    including the suggested value and submitted value. The acceptance score is
    calculated server-side based on whether the values match. For features that
    support semantic similarity (title, description, statement, mitigation),
    semantic proximity scoring is attempted. If semantic scoring fails or times out,
    the entry remains with an empty acceptance_score and can be retried later.
    """
    from datetime import datetime

    try:
        feature = feedback.feature
        cve_id = feedback.cve_id or ""
        email = feedback.email or ""
        suggested = feedback.suggested_value or ""
        submitted = feedback.submitted_value or ""

        # Generate datetime once at the start to ensure consistency
        entry_datetime = datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]

        # Calculate exact match score (fallback)
        acceptance_score = calculate_acceptance_score(suggested, submitted)

        acceptance_score_str = (
            str(acceptance_score) if acceptance_score is not None else ""
        )

        row_data = {
            "datetime": entry_datetime,  # Use the same datetime for CSV logging
            "feature": feature,
            "cve_id": cve_id,
            "email": email,
            "suggested_value": suggested,
            "submitted_value": submitted,
            "acceptance_score": acceptance_score_str,
            "llmjudge_explanation": "",  # Will be populated by semantic scoring if LLMJudge is used
        }

        # Write CSV entry first (semantic scoring will update it if successful)
        programmatic_feedback_logger.write(row_data)

        # Start semantic scoring as a background task (non-blocking)
        # This allows the feedback submission to complete quickly while
        # semantic scoring runs in the background
        asyncio.create_task(
            process_semantic_scoring(
                feature=feature,
                suggested=suggested,
                submitted=submitted,
                cve_id=cve_id,
                entry_datetime=entry_datetime,
                email=email,
            )
        )

        logging.info(
            f"Programmatic feedback logged: feature={feature}, cve_id={cve_id}"
        )
        return {"status": "Programmatic feedback received and logged successfully."}

    except HTTPException:
        # Re-raise HTTP exceptions (like 409 Conflict) without wrapping
        raise
    except Exception as e:
        entry = f"{feedback.cve_id}/{feedback.feature}"
        logging.warning(
            f"Failed to process programmatic feedback for {entry}: {e.__class__.__name__}"
        )
        logging.debug(
            f"Error details for programmatic feedback submission {entry}: {e}",
            exc_info=True,
        )
        raise HTTPException(
            status_code=500,
            detail="An internal error occurred while processing programmatic feedback.",
        )
